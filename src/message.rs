use crate::types::{AccessList, Hash};
use crate::types::{CapabilityMessage, CapabilityName, HelloMessage, Transaction};
use crate::utils;
use arrayvec::ArrayString;
use num::BigUint;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use sha3::{Digest, Keccak256};

const BASE_PROTOCOL_VERSION: usize = 5;

pub fn create_pong_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x03];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_transaction(payload: Vec<u8>) -> Transaction {
    let transaction = rlp::Rlp::new(&payload);

    let mut hasher = Keccak256::new();

    if transaction.is_list() {
        // Transaction legacy

        hasher.update(&transaction.as_raw());
        let txid = hasher.finalize().to_vec();

        let nonce: u32 = transaction.at(0).unwrap().as_val().unwrap();
        // NOTE: there is a transaction in Ropsten where gas_price is bigger than u64
        let gas_price: Vec<u8> = transaction.at(1).unwrap().as_val().unwrap();
        let gas_limit: u64 = transaction.at(2).unwrap().as_val().unwrap();
        let to: Vec<u8> = transaction.at(3).unwrap().as_val().unwrap();
        let value: Vec<u8> = transaction.at(4).unwrap().as_val().unwrap();
        let data: Vec<u8> = transaction.at(5).unwrap().as_val().unwrap();
        let v: u64 = transaction.at(6).unwrap().as_val().unwrap();
        let r: Vec<u8> = transaction.at(7).unwrap().as_val().unwrap();
        let s: Vec<u8> = transaction.at(8).unwrap().as_val().unwrap();

        // Calculate from address
        let mut rlps = rlp::RlpStream::new();
        rlps.begin_unbounded_list();
        for n in 0..=5 {
            rlps.append_raw(transaction.at(n).unwrap().as_raw(), 1);
        }
        if v > 28 {
            // TODO: This is not right...
            let chain_id = v / 2;

            rlps.append(&chain_id);
            rlps.append(&0_u8);
            rlps.append(&0_u8);
        }
        rlps.finalize_unbounded_list();

        let mut hasher = Keccak256::new();
        hasher.update(&rlps.as_raw());
        let digest = hasher.finalize();

        // Get public key here and therefore address
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let recid = match v {
            0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
            27 => RecoveryId::from_i32(0).unwrap(),
            28 => RecoveryId::from_i32(1).unwrap(),
            _ => {
                let v = (v - 35) % 2;
                RecoveryId::from_i32(v as i32).unwrap()
            }
        };
        let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
        let pubkey = sig.recover(&msg).unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize_uncompressed()[1..]);
        let from: Vec<u8> = hasher.finalize()[12..].to_vec();

        return Transaction {
            chain_id: None,
            nonce,
            gas_price: Some(BigUint::from_bytes_be(&gas_price)),
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            gas_limit,
            to,
            value: BigUint::from_bytes_be(&value),
            data,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            v,
            r,
            s,
            txid,
            from,
            tx_type: 0,
        };
    }

    let eip_tx: Vec<u8> = transaction.as_val().unwrap();
    let t = rlp::Rlp::new(&eip_tx[1..]);
    assert!(t.is_list());

    hasher.update(&eip_tx);
    let txid = hasher.finalize().to_vec();

    match eip_tx[0] {
        1 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let gas_price: Vec<u8> = t.at(2).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(3).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(4).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(7).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let v: u64 = t.at(8).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(9).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(10).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=7 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x01u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: Some(BigUint::from_bytes_be(&gas_price)),
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                v,
                r,
                s,
                txid,
                from,
                tx_type: 1,
            }
        }
        2 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let max_priority_fee_per_gas: u64 = t.at(2).unwrap().as_val().unwrap();
            let max_fee_per_gas: u64 = t.at(3).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(4).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(7).unwrap().as_val().unwrap();

            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(8).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let v: u64 = t.at(9).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(10).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(11).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=8 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x02u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: None,
                max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
                max_fee_per_gas: Some(max_fee_per_gas),
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                v,
                r,
                s,
                txid,
                from,
                tx_type: 2,
            }
        }
        3 => {
            let chain_id: u64 = t.at(0).unwrap().as_val().unwrap();
            let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
            let max_priority_fee_per_gas: u64 = t.at(2).unwrap().as_val().unwrap();
            let max_fee_per_gas: u64 = t.at(3).unwrap().as_val().unwrap();
            let gas_limit: u64 = t.at(4).unwrap().as_val().unwrap();
            let to: Vec<u8> = t.at(5).unwrap().as_val().unwrap();
            let value: Vec<u8> = t.at(6).unwrap().as_val().unwrap();
            let data: Vec<u8> = t.at(7).unwrap().as_val().unwrap();

            let mut access_list: AccessList = AccessList(vec![]);
            let tmp = t.at(8).unwrap();
            for n in 0..tmp.item_count().unwrap() {
                let access = tmp.at(n).unwrap();
                assert!(access.is_list());

                let key: Vec<u8> = access.at(0).unwrap().as_val().unwrap();
                let list: Vec<Hash> = access
                    .at(1)
                    .unwrap()
                    .as_list::<Vec<u8>>()
                    .unwrap()
                    .iter()
                    .map(|list| Hash(list.to_vec()))
                    .collect();

                access_list.0.push((Hash(key), list));
            }
            assert_eq!(access_list.0.len(), tmp.item_count().unwrap());
            let max_fee_per_blob_gas: u32 = t.at(9).unwrap().as_val().unwrap();
            let blob_versioned_hashes: Vec<Hash> = t
                .at(10)
                .unwrap()
                .as_list::<Vec<u8>>()
                .unwrap()
                .iter()
                .map(|h| {
                    let h = rlp::Rlp::new(&h);
                    assert!(h.is_list());

                    let hash: Vec<u8> = h.as_val().unwrap();
                    Hash(hash)
                })
                .collect();
            let v: u64 = t.at(11).unwrap().as_val().unwrap();
            let r: Vec<u8> = t.at(12).unwrap().as_val().unwrap();
            let s: Vec<u8> = t.at(13).unwrap().as_val().unwrap();

            // Calculate from address
            let mut rlps = rlp::RlpStream::new();
            rlps.begin_unbounded_list();
            for n in 0..=10 {
                rlps.append_raw(t.at(n).unwrap().as_raw(), 1);
            }
            if v > 28 {
                // TODO: This is not right...
                let chain_id = v / 2;

                rlps.append(&chain_id);
                rlps.append(&0_u8);
                rlps.append(&0_u8);
            }
            rlps.finalize_unbounded_list();

            let mut hasher = Keccak256::new();
            hasher.update([&[0x03u8], rlps.as_raw()].concat());
            let digest = hasher.finalize();

            // Get public key here and therefore address
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
            let recid = match v {
                0 | 1 | 2 | 3 => RecoveryId::from_i32(v as i32).unwrap(),
                27 => RecoveryId::from_i32(0).unwrap(),
                28 => RecoveryId::from_i32(1).unwrap(),
                _ => {
                    let v = (v - 35) % 2;
                    RecoveryId::from_i32(v as i32).unwrap()
                }
            };
            let sig = RecoverableSignature::from_compact(&utils::get_sig(&r, &s), recid).unwrap();
            let pubkey = sig.recover(&msg).unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(&pubkey.serialize_uncompressed()[1..]);
            let from: Vec<u8> = hasher.finalize()[12..].to_vec();

            Transaction {
                chain_id: Some(chain_id),
                nonce,
                gas_price: None,
                max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
                max_fee_per_gas: Some(max_fee_per_gas),
                gas_limit,
                to,
                value: BigUint::from_bytes_be(&value),
                data,
                access_list: Some(access_list),
                max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
                blob_versioned_hashes: Some(blob_versioned_hashes),
                v,
                r,
                s,
                txid,
                from,
                tx_type: 3,
            }
        }
        _ => {
            dbg!(hex::encode(&payload));
            todo!("others type not supported yet");
        }
    }
}

pub fn create_hello_message(private_key: &Vec<u8>) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello = HelloMessage {
        protocol_version: BASE_PROTOCOL_VERSION,
        client_version: String::from("deadbrain corp."),
        capabilities: vec![
            //CapabilityMessage{ name: CapabilityName(ArrayString::from("eth").unwrap()), version: 66 },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 67,
            },
            CapabilityMessage {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 68,
            },
        ],
        // capabilities: vec![types::CapabilityMessage{ name: types::CapabilityName(ArrayString::from("les").unwrap()), version: 4 }],
        port: 0,
        id: primitive_types::H512::from_slice(
            &secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
                [1..],
        ),
    };

    let payload = rlp::encode(&hello);
    let code: Vec<u8> = vec![0x80];
    // Add HELLO code in front
    let message = [code.to_vec(), payload.to_vec()].concat();

    return message;
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::parse_transaction;

    #[test]
    fn test_parsing_eip_tx() {
        let tx_payload = hex::decode("b9025301f9024f01820f248502e0b6a20083124f8094391fb6e28870b1ec24780510740412f6d35e914180b901e4c5d4049400000000000000000000000000000000000000000000000006abc1dde328d9fd000000000000000000000000000000000000000000000000000e7da5a11c20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000300000000000000000000000080ddbeeb05788980caa0b1b433b40d4443f4439e000000000000000000000000c690f7c7fcffa6a82b79fab7508c466fefdfc8c50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c8aa5662c8708225bfdf7f6ce3267579de8f2d06000000000000000000000000d9016a907dc0ecfa3ca425ab20b6b785b42f237300000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c083084c9d50334b343c44ec97d16011303cc73000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000c001a091d97db642adc9a42eb50ff9a2dfeaf506b7893813193238d47ac52f2a143ef5a01374208cc47aaa780669b9afba49bc2a44f7a7911a0e0e14d7ea3de70c98af0d").unwrap();

        let t = parse_transaction(tx_payload);
        assert_eq!(
            "af9f790423edbdb566b915555ddb4c45b92936232006bca0622f262fa3859704",
            hex::encode(&t.txid)
        );
    }

    #[test]
    fn test_verify_signature() {
        use sha3::{Digest, Keccak256};

        let tx_payload = hex::decode("b9025301f9024f01820f248502e0b6a20083124f8094391fb6e28870b1ec24780510740412f6d35e914180b901e4c5d4049400000000000000000000000000000000000000000000000006abc1dde328d9fd000000000000000000000000000000000000000000000000000e7da5a11c20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000300000000000000000000000080ddbeeb05788980caa0b1b433b40d4443f4439e000000000000000000000000c690f7c7fcffa6a82b79fab7508c466fefdfc8c50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c8aa5662c8708225bfdf7f6ce3267579de8f2d06000000000000000000000000d9016a907dc0ecfa3ca425ab20b6b785b42f237300000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c083084c9d50334b343c44ec97d16011303cc73000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000c001a091d97db642adc9a42eb50ff9a2dfeaf506b7893813193238d47ac52f2a143ef5a01374208cc47aaa780669b9afba49bc2a44f7a7911a0e0e14d7ea3de70c98af0d").unwrap();

        let transaction = rlp::Rlp::new(&tx_payload);
        assert!(!transaction.is_list());
        let eip_tx: Vec<u8> = transaction.as_val().unwrap();

        // Should be a transaction type 1
        assert_eq!(eip_tx[0], 1);

        let t = rlp::Rlp::new(&eip_tx[1..]);
        assert!(t.is_list());

        let chain_id: u32 = t.at(0).unwrap().as_val().unwrap();
        let nonce: u32 = t.at(1).unwrap().as_val().unwrap();
        let gas_price: u64 = t.at(2).unwrap().as_val().unwrap();
        let gas_limit: u64 = t.at(3).unwrap().as_val().unwrap();
        let to = t.at(4).unwrap().as_raw().to_vec();
        let value = t.at(5).unwrap().as_raw().to_vec();
        let data = t.at(6).unwrap().as_raw().to_vec();
        let access_list = t.at(7).unwrap().as_raw().to_vec();

        let mut s = rlp::RlpStream::new();
        s.begin_unbounded_list();
        s.append(&chain_id);
        s.append(&nonce);
        s.append(&gas_price);
        s.append(&gas_limit);
        s.append(&to);
        s.append(&value);
        s.append(&data);
        s.append_raw(&access_list, 1);

        s.finalize_unbounded_list();

        let mut hasher = Keccak256::new();
        hasher.update(&s.as_raw());
        let digest = hasher.finalize();

        let v: u32 = t.at(8).unwrap().as_val().unwrap();
        let r = t.at(9).unwrap().as_raw().to_vec();
        let s = t.at(10).unwrap().as_raw().to_vec();

        let mut sig_data: Vec<u8> = vec![];
        sig_data.append(&mut r[1..].to_vec());
        sig_data.append(&mut s[1..].to_vec());

        let recid = secp256k1::ecdsa::RecoveryId::from_i32(v as i32).unwrap();

        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_data, recid).unwrap();

        let _pubkey = secp256k1::SECP256K1.recover_ecdsa(&msg, &sig).unwrap();
    }

    #[test]
    fn test_parse_type2() {
        let tx_payload = hex::decode("b8b602f8b301820105850712ca0300850789ff970082b88694491d6b7d6822d5d4bc88a1264e1b47791fd8e90480b844095ea7b30000000000000000000000007645eec8bb51862a5aa855c40971b2877dae81afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc001a0416470241b7db89c67526881b6fd8e145416b294a35bf4280d3079f6308c2d11a02c0af1cc55c22c0bab79ec083801da63253453156356fcd4291f50d0f425a0ee").unwrap();

        let t = parse_transaction(tx_payload);
        assert_eq!(
            "ed382cb554ad10e94921d263a56c670669d6c380bbdacdbf96fed625b7132a1d",
            hex::encode(&t.txid)
        );
    }
}
