use aes::cipher::KeyIvInit;
use devp2p::{ecies::ECIES, util::pk2id};
use eth_prototype::{mac, message, utils};
use secp256k1_20::{PublicKey, SecretKey, SECP256K1};
use sha3::{Digest, Keccak256};

#[test]
fn communicate() {
    let server_secret_key = SecretKey::from_slice(&[1_u8; 32]).unwrap();
    let server_public_key = PublicKey::from_secret_key(SECP256K1, &server_secret_key);

    let remote_id = pk2id(&server_public_key).0.to_vec();
    let private_key =
        hex::decode("472D4B6150645267556B58703273357638792F423F4528482B4D625165546856").unwrap();
    // Should be generated randomly
    let nonce =
        hex::decode("09267e7d55aada87e46468b2838cc616f084394d6d600714b58ad7a3a2c0c870").unwrap();
    // Epheremal private key (should be random)
    let ephemeral_privkey =
        hex::decode("691bb7a2fd6647eae78a235b9d305d09f796fe8e8ce7a18aa1aa1deff9649a02").unwrap();
    // Pad (should be generated randomly)
    let pad = [0_u8; 100].to_vec();

    let mut server_ecies = ECIES::new_server(server_secret_key).unwrap();

    let mut init_msg =
        utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // Handshake
    server_ecies.read_auth(&mut init_msg).unwrap();
    let ack = server_ecies.create_ack();

    let shared_mac_data = &ack[0..2];
    let payload = &ack[2..];

    let decrypted =
        utils::decrypt_message(&payload.to_vec(), &shared_mac_data.to_vec(), &private_key);
    dbg!(hex::encode(&decrypted));

    // decode RPL data
    let decoded = rlp::decode_list::<Vec<u8>>(&decrypted);

    // id to pubkey
    let remote_ephemeral_public_key: Vec<u8> = [vec![0x04], decoded[0].to_vec()].concat();
    dbg!(hex::encode(&remote_ephemeral_public_key));
    let remote_nonce = &decoded[1];
    let ephemeral_shared_secret = utils::ecdh_x(&remote_ephemeral_public_key, &ephemeral_privkey);

    dbg!(hex::encode(&ephemeral_shared_secret));

    let server_to_client_data = [0_u8, 1_u8, 2_u8, 3_u8, 4_u8];

    /******************
     *
     *  Setup Frame
     *
     ******************/

    let nonce_material = [remote_nonce.to_vec(), nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize();

    dbg!(hex::encode(&h_nonce));

    let iv = [0u8; 16];
    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(h_nonce);
    let shared_secret = hasher.finalize();

    dbg!(hex::encode(&shared_secret));

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(shared_secret);
    let aes_secret = hasher.finalize();

    dbg!(hex::encode(&aes_secret));

    let mut ingress_aes = utils::Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());
    let mut egress_aes = utils::Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(aes_secret);
    let mac_secret = hasher.finalize();

    dbg!(hex::encode(&mac_secret));

    // The MAC thingy is actually keccak256

    let remote_data = [shared_mac_data, &payload].concat();

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

    // Test server to client 1
    let header = server_ecies.create_header(server_to_client_data.len());
    assert_eq!(header.len(), ECIES::header_len());

    let next_size = utils::parse_header(&header.to_vec(), &mut ingress_mac, &mut ingress_aes);
    dbg!(next_size);

    let body = server_ecies.create_body(&server_to_client_data);
    dbg!(body.len());
    let ret = utils::parse_body(
        &body.to_vec(),
        &mut ingress_mac,
        &mut ingress_aes,
        next_size,
    );
    assert_eq!(ret, server_to_client_data);

    // Test client to server 1
    let hello = message::create_hello_message(&private_key);
    let mut header = utils::create_header(hello.len(), &mut egress_mac, &mut egress_aes);

    let _ = server_ecies.read_header(&mut header);

    let mut body = utils::create_body(hello, &mut egress_mac, &mut egress_aes);

    let _ = server_ecies.read_body(&mut body);
}

#[test]
fn communicate2() {
    let server_secret_key = SecretKey::from_slice(&[1_u8; 32]).unwrap();
    let server_public_key = PublicKey::from_secret_key(SECP256K1, &server_secret_key);

    let private_key =
        hex::decode("472D4B6150645267556B58703273357638792F423F4528482B4D625165546856").unwrap();

    let client_secret_key = SecretKey::from_slice(&private_key).unwrap();

    let mut server_ecies = ECIES::new_server(server_secret_key).unwrap();
    let mut client_ecies = ECIES::new_client(client_secret_key, pk2id(&server_public_key)).unwrap();

    // Handshake
    let mut auth = client_ecies.create_auth();
    server_ecies.read_auth(&mut auth).unwrap();
    let mut ack = server_ecies.create_ack();
    client_ecies.read_ack(&mut ack).unwrap();

    let server_to_client_data = [0_u8, 1_u8, 2_u8, 3_u8, 4_u8];

    // Test server to client 1
    let mut header = server_ecies.create_header(server_to_client_data.len());
    assert_eq!(header.len(), ECIES::header_len());
    client_ecies.read_header(&mut *header).unwrap();
}
