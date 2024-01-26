use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::ByteOrder;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use hmac_sha256::{Hash, HMAC};
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Keccak256};
use std::borrow::BorrowMut;
use std::io::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use super::mac;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;
const READ_MESSAGE_TIME_MS: u64 = 1;

pub fn ecdh_x(pubkey: &Vec<u8>, privkey: &Vec<u8>) -> Vec<u8> {
    let sk = k256::ecdsa::SigningKey::from_slice(privkey).unwrap();
    let pk = k256::PublicKey::from_sec1_bytes(pubkey).unwrap();
    let shared_secret =
        k256::elliptic_curve::ecdh::diffie_hellman(sk.as_nonzero_scalar(), pk.as_affine());

    shared_secret.raw_secret_bytes().to_vec()
}

pub fn concat_kdf(key_material: Vec<u8>, key_length: usize) -> Vec<u8> {
    const SHA256_BLOCK_SIZE: usize = 64;
    let reps = ((key_length + 7) * 8) / (SHA256_BLOCK_SIZE * 8);
    let mut counter = 0;

    let mut buffers: Vec<Vec<u8>> = vec![];

    while counter <= reps {
        counter += 1;
        let mut tmp: Vec<u8> = vec![];
        let _ = tmp.write_u32::<BigEndian>(counter as u32);
        let mut hash = Hash::new();
        hash.update(tmp);
        hash.update(&key_material);
        buffers.push(hash.finalize().into());
    }

    let mut result: Vec<u8> = vec![];
    buffers.iter().for_each(|x| result.extend(x));

    return result[0..key_length].to_vec();
}

pub fn encrypt_message(
    remote_public: &Vec<u8>,
    mut data: Vec<u8>,
    shared_mac_data: &Vec<u8>,
) -> Vec<u8> {
    let privkey = k256::SecretKey::random(&mut OsRng);
    let x = ecdh_x(remote_public, &privkey.to_bytes().to_vec());
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // encrypt
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let mut cipher = Aes128Ctr64BE::new(e_key.into(), &iv.into());
    cipher.apply_keystream(&mut data);

    let mut data_iv: Vec<u8> = vec![];
    data_iv.extend(iv);
    data_iv.extend(data);

    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let tag = HMAC::mac(input, m_key);

    let public_key = privkey.public_key();
    let vkey = k256::ecdsa::VerifyingKey::from(public_key);
    let uncompressed_pubkey_bytes = vkey.to_encoded_point(false).to_bytes();

    let mut result: Vec<u8> = vec![];

    result.extend(uncompressed_pubkey_bytes.to_vec());
    result.extend(data_iv);
    result.extend(tag);

    return result;
}

pub fn decrypt_message(
    payload: &Vec<u8>,
    shared_mac_data: &Vec<u8>,
    private_key: &Vec<u8>,
) -> Vec<u8> {
    assert_eq!(payload[0], 0x04);

    let public_key = payload[0..65].to_vec();
    let data_iv = payload[65..(payload.len() - 32)].to_vec();
    let tag = payload[(payload.len() - 32)..].to_vec();

    // derive keys
    let x = ecdh_x(&public_key, private_key);
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // check the tag
    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let _tag = HMAC::mac(input, m_key).to_vec();

    assert_eq!(_tag, tag);

    // decrypt data
    let iv = &data_iv[0..16];
    let mut encrypted_data = data_iv[16..].to_vec();
    let mut decipher = Aes128Ctr64BE::new(e_key.into(), iv.into());
    // decipher encrypted_data and return result in encrypted_data variable
    decipher.apply_keystream(&mut encrypted_data);

    return encrypted_data;
}

pub fn create_auth_eip8(
    remote_id: &Vec<u8>,
    private_key: &Vec<u8>,
    nonce: &Vec<u8>,
    ephemeral_privkey: &Vec<u8>,
    pad: &Vec<u8>,
) -> Vec<u8> {
    let mut auth_message: Vec<u8> = vec![];
    // Add 04 to the remote ID to get the remote public key
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    // ECDH stuff
    let shared_secret = ecdh_x(&remote_public_key, &private_key);

    // XOR pubkey and nonce
    let msg_hash: Vec<u8> = shared_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    // sign message
    let ephemeral_signing_key = secp256k1::SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let (recid, sig) = secp256k1::SECP256K1
        .sign_ecdsa_recoverable(
            &secp256k1::Message::from_slice(&msg_hash).unwrap(),
            &ephemeral_signing_key,
        )
        .serialize_compact();

    // convert to RSV
    let mut rsv_sig = sig.to_vec();

    // adding signing id
    rsv_sig.push(recid.to_i32() as u8);

    // Initialize array with empty vectors
    let sk = k256::ecdsa::SigningKey::from_slice(&private_key).unwrap();
    let vkey = sk.verifying_key();
    let uncompressed_pubkey_bytes = vkey.to_encoded_point(false).to_bytes();

    let data = vec![
        rsv_sig,
        uncompressed_pubkey_bytes[1..].to_vec(),
        nonce.to_vec(),
        vec![0x04],
    ];

    // Encoded RLP data
    let encoded_data = rlp::encode_list::<Vec<u8>, _>(&data);

    // Concat padding to the encoded data
    auth_message.extend(encoded_data.to_vec());
    auth_message.extend(pad);

    let overhead_length = 113;
    let mut shared_mac_data: Vec<u8> = vec![];
    let _ = shared_mac_data.write_u16::<BigEndian>((auth_message.len() + overhead_length) as u16);

    // Encrypt message
    let enrcyped_auth_message = encrypt_message(&remote_public_key, auth_message, &shared_mac_data);

    let init_msg = [shared_mac_data, enrcyped_auth_message].concat();

    return init_msg;
}

pub fn setup_frame(
    remote_nonce: Vec<u8>,
    nonce: Vec<u8>,
    ephemeral_shared_secret: Vec<u8>,
    remote_data: Vec<u8>,
    init_msg: Vec<u8>,
) -> (Aes256Ctr64BE, mac::MAC, Aes256Ctr64BE, mac::MAC) {
    let nonce_material = [remote_nonce.clone(), nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize();

    let iv = [0u8; 16];
    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(h_nonce);
    let shared_secret = hasher.finalize();

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(shared_secret);
    let aes_secret = hasher.finalize();

    let ingress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());
    let egress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(aes_secret);
    let mac_secret = hasher.finalize();

    // The MAC thingy is actually keccak256

    // let remote_data = [shared_mac_data, &payload].concat();

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut ingress_mac = mac::MAC::new(mac_secret.to_vec());
    ingress_mac.update(&[xor_result, remote_data].concat());

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(remote_nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut egress_mac = mac::MAC::new(mac_secret.to_vec());
    egress_mac.update(&[xor_result, init_msg].concat());

    return (ingress_aes, ingress_mac, egress_aes, egress_mac);
}

// NOTE: could be [u8; 32]
pub fn parse_header(
    data: &Vec<u8>,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> usize {
    let mut header = data[0..16].to_vec();
    let mac = &data[16..32];

    ingress_mac.update_header(&mut header);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut header);
    let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3).unwrap()).unwrap();
    return body_size;
}

pub fn parse_body(
    data: &Vec<u8>,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
    body_size: usize,
) -> Vec<u8> {
    let mut body = data[0..data.len() - 16].to_vec();
    let mac = &data[data.len() - 16..];

    /* Something about mac that we are missing */
    ingress_mac.update_body(&mut body);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut body);

    return body[0..body_size].to_vec();
}

pub fn get_body_len(size: usize) -> usize {
    (if size % 16 == 0 {
        size
    } else {
        (size / 16 + 1) * 16
    }) + 16
}

pub fn create_header(
    length: usize,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let mut buf = [0; 8];
    BigEndian::write_uint(&mut buf, length as u64, 3);
    let mut header = [0_u8; 16];
    header[0..3].copy_from_slice(&buf[0..3]);

    egress_aes.apply_keystream(&mut header);
    egress_mac.update_header(&mut header.to_vec());

    let tag = egress_mac.digest();

    return [header.to_vec(), tag].concat().to_vec();
}

pub fn create_body(
    body: Vec<u8>,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let body_len = get_body_len(body.len()) - 16;

    let mut body_message = vec![0; body_len];
    body_message[..body.len()].clone_from_slice(&body);

    egress_aes.apply_keystream(&mut body_message);
    egress_mac.update_body(&mut body_message.to_vec());
    let tag = egress_mac.digest();

    return [body_message.to_vec(), tag].concat().to_vec();
}

pub fn send_message(
    msg: Vec<u8>,
    stream: &mut std::net::TcpStream,
    egress_mac: &Arc<Mutex<mac::MAC>>,
    egress_aes: &Arc<Mutex<Aes256Ctr64BE>>,
) {
    let mut egress_aes = egress_aes.lock().unwrap();
    let mut egress_mac = egress_mac.lock().unwrap();

    let header = create_header(msg.len(), egress_mac.borrow_mut(), egress_aes.borrow_mut());

    stream.write(&header).unwrap();
    stream.flush().unwrap();

    let body = create_body(msg, egress_mac.borrow_mut(), egress_aes.borrow_mut());

    stream.write(&body).unwrap();
    stream.flush().unwrap();
}

pub fn read_message(
    stream: &mut std::net::TcpStream,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let mut buf = [0u8; 32];
    let mut size = stream.read(&mut buf).unwrap();

    while size == 0 {
        thread::sleep(Duration::from_millis(READ_MESSAGE_TIME_MS));
        size = stream.read(&mut buf).unwrap();
    }

    assert_eq!(size, 32);

    let next_size = parse_header(&buf.to_vec(), ingress_mac, ingress_aes);

    // Message payload
    let mut body: Vec<u8> = vec![];
    let body_size = get_body_len(next_size);

    // we have this loop to be sure we have received the complete payload
    while body.len() < body_size {
        let mut buf: Vec<u8> = vec![0; body_size - body.len()];
        let l = stream.read(&mut buf).unwrap();

        body.extend(&buf[0..l]);
        thread::sleep(Duration::from_millis(READ_MESSAGE_TIME_MS));
    }

    assert_eq!(body.len(), body_size);

    let uncrypted_body = parse_body(&body, ingress_mac, ingress_aes, next_size);

    return uncrypted_body;
}

#[cfg(test)]
mod tests {
    use super::{ecdh_x, Aes256Ctr64BE};
    use crate::mac::MAC;
    use aes::cipher::KeyIvInit;
    use sha3::Digest;
    use sha3::Keccak256;

    #[test]
    fn test_parse_header() {
        let data = hex::decode("2f58e3c6bb1d5de6d29dd182b088b41c07da694b1c6eb0089168fa515a38de21")
            .unwrap();

        let header = &data[0..16];
        let mac = &data[16..32];

        dbg!(hex::encode(&header));

        let secret =
            hex::decode("0e4dcf62fddcd340f169f75321fa25762d827d3d3729e3865160952d50ae9980")
                .unwrap();
        let mut ingress_mac = MAC::new(secret);

        let data = hex::decode("0d7de5adac1e9b05e39e2251bbd6631b8f34f7690686e5fafa3b86d4d00d7309018a045df41051a3d36084c7755289c4d052737a6c8e3ffa79c0e60d206a57951adf4f453d4dde75d9f139d010a154fecbf30f680c9362aff421cd15dc712675c9879e2b0c8fda3f0ca3158f8665143105f17b8ec654db94fd2873ce5937c86019e223f62489168d1c7c55ff81b30893316be0e19cd338b41d73d99424a4c1b95071a1bec968909a8d8e5c0b541a5eb3a5f03df52ad302c49920c25c6668b02de083765bb3e57ade8e98f1cf5d10f17a7b3936a77f76442ec2c779d670a18455093756d33be5d30d5cf21cc118c3c1fc1b87d7810d69703b33a3560758b4f6b2ece87123c3daf753f33c264d710818a7cfbbe3bea3bbd72cd64a2a74ad92e5c807284c64317e1c792e740731c2ac20cebd51c7c27e378a73e6fd55d2fc73099ed2c05d337dc3c7ba728e9a2d7527049dbd6ccfae5610b13927469809e1e52dfb0e6bb176faff29e57cb829f350edc641df6951454a68d07862960e041e2ed03bdd7935cf13d15ecbd37247cb0113aa58473641dfdc948f3885a0b0f2ebad9be385030b7a8c96719683fce712").unwrap();
        ingress_mac.update(&data);
        ingress_mac.update_header(&mut header.to_vec());
        let _mac = ingress_mac.digest();

        assert_eq!(_mac, mac);
    }

    #[test]
    fn test_setup_frame() {
        let remote_nonce =
            hex::decode("2402e143d3c04ce598b723d3ba2d0d757b0bec66e4087ee21faa7fd1dd2bd590")
                .unwrap();
        let nonce = hex::decode("7ffc0228f4a7d5b853a6dc301691561436b3c68c62c44f4ffa456c54dab7611f")
            .unwrap();
        let ephemeral_shared_secret =
            hex::decode("184620303882579dbeb558c042989a8a0f00beb6bdf5f90882f133f676788df7")
                .unwrap();

        let nonce_material = [remote_nonce.to_vec(), nonce.clone()].concat();
        let mut hasher = Keccak256::new();
        hasher.update(&nonce_material);
        let h_nonce = hasher.finalize();

        assert_eq!(
            h_nonce.to_vec(),
            hex::decode("4fcce44ac9e5c335cb369eab56581fd6ca58d209bb86f25f8372c546163d15bf")
                .unwrap()
        );

        let iv = [0u8; 16];
        let mut hasher = Keccak256::new();
        hasher.update(&ephemeral_shared_secret);
        hasher.update(h_nonce);
        let shared_secret = hasher.finalize();

        assert_eq!(
            shared_secret.to_vec(),
            hex::decode("506874951bc21614d35452ca1f115da71d7f7250424eec53d189ea8c64ae9843")
                .unwrap()
        );

        let mut hasher = Keccak256::new();
        hasher.update(&ephemeral_shared_secret);
        hasher.update(shared_secret);
        let aes_secret = hasher.finalize();

        assert_eq!(
            aes_secret.to_vec(),
            hex::decode("983509e7b115aaf9835802864eb974c85e89a793212d6542338a510b7366dbba")
                .unwrap()
        );

        let mut _ingress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());
        // let mut egress_aes = utils::Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());

        let mut hasher = Keccak256::new();
        hasher.update(&ephemeral_shared_secret);
        hasher.update(aes_secret);
        let mac_secret = hasher.finalize();
        assert_eq!(
            mac_secret.to_vec(),
            hex::decode("3b8864f7c1fe60f6c7cd6079e26545e1fdc7cda84ab04e64d82a9cb465ef5009")
                .unwrap()
        );

        let remote_data = hex::decode("0172040723f64a3dce435d963eccc4bbe6f2a22288f1a30ebfa0d044cd099683a2e6ca719473a86730d846b20b795a2bbf4a3a6cbcc273c3646238721873810d5d4c409abe1fd4c9df3c6b379db1db4fb7cf9928fe45a0270fb6ef6cf73f307c09c3b086051ae4d7a62aae2a6c81796304f393da68fca3668d2ad03430aadf5455beb3f8c39123bc71e5ec43e6c84731570342428ff204fce74e5b4230566287ab1b3b84ef87ace60014e13a010d2a844238c4af3832a78b43f06507abaa9a02be2f58a1594edf061829030cd9f6a719e39720ea75616d684bb204a9988fa57fc131291a82810fdafdfd4a11b58d144659a1140c9a0769349ca471e0fffdfabe52aecb30d0fba0ae564494e9189cf7efee254348fa7080ff6f2c4ad715f9a8804def9d34bec291e464e0e831fcfaee1d9622f34158c28eb3697cfcbff3399da9cea7b07a813b901e548ae145fc1eb4f1c0c0694448eadfb81298815ec2a9a5fee242007fedd6843873ae6161984ffcef07489e8b").unwrap();
        let xor_result: Vec<u8> = mac_secret
            .iter()
            .zip(nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        let data = [xor_result, remote_data].concat();
        assert_eq!(data.to_vec(), hex::decode("447466df3559b54e946bbc49f4f413f5cb740b242874012b226ff0e0bf5831160172040723f64a3dce435d963eccc4bbe6f2a22288f1a30ebfa0d044cd099683a2e6ca719473a86730d846b20b795a2bbf4a3a6cbcc273c3646238721873810d5d4c409abe1fd4c9df3c6b379db1db4fb7cf9928fe45a0270fb6ef6cf73f307c09c3b086051ae4d7a62aae2a6c81796304f393da68fca3668d2ad03430aadf5455beb3f8c39123bc71e5ec43e6c84731570342428ff204fce74e5b4230566287ab1b3b84ef87ace60014e13a010d2a844238c4af3832a78b43f06507abaa9a02be2f58a1594edf061829030cd9f6a719e39720ea75616d684bb204a9988fa57fc131291a82810fdafdfd4a11b58d144659a1140c9a0769349ca471e0fffdfabe52aecb30d0fba0ae564494e9189cf7efee254348fa7080ff6f2c4ad715f9a8804def9d34bec291e464e0e831fcfaee1d9622f34158c28eb3697cfcbff3399da9cea7b07a813b901e548ae145fc1eb4f1c0c0694448eadfb81298815ec2a9a5fee242007fedd6843873ae6161984ffcef07489e8b").unwrap());
    }

    #[test]
    fn test_decode_rlp() {
        let decrypted = hex::decode("f864b8407c204bda850973caf45ffc114ff007e9a83c235108fd27489dba134b1bf47ac3c362d217634ec6138ee9adbfbad3cb1e2022d9e1320168e057ab8e76b51b2d4ca0ad28cc8c578fc07e766a1d0aaf6372b57a05eafc051b4e2d4fff17bc886d320f04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        // decode RPL data
        let decoded = rlp::decode_list::<Vec<u8>>(&decrypted);

        assert_eq!(decoded[0], hex::decode("7c204bda850973caf45ffc114ff007e9a83c235108fd27489dba134b1bf47ac3c362d217634ec6138ee9adbfbad3cb1e2022d9e1320168e057ab8e76b51b2d4c").unwrap());
        assert_eq!(
            decoded[1],
            hex::decode("ad28cc8c578fc07e766a1d0aaf6372b57a05eafc051b4e2d4fff17bc886d320f")
                .unwrap()
        );
    }

    #[test]
    fn test_ecdh_x() {
        let ephemeral_private_key =
            hex::decode("645fb05f68f5401fb1cd05f7cc3b2d4a04568e95a258ed0a01e7e3c91cce6c59")
                .unwrap();
        let remote_ephemeral_public_key = hex::decode("043724e7db558c67bb6c5245d373a1db8fbaa218d225321dc14c73c316450307f55952a4917ba22430fa6862b32fc69f6afe675f17b2ff47497fe80f8475923fe8").unwrap();

        let ephemeral_shared_secret = ecdh_x(&remote_ephemeral_public_key, &ephemeral_private_key);

        assert_eq!(
            ephemeral_shared_secret,
            hex::decode("8467b2a5e12124c7825466d59e10c09981ce25172bde9864853a081b12412267")
                .unwrap()
        );
    }
}
