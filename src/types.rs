use arrayvec::ArrayString;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::Serialize;
use num::BigUint;

#[derive(Clone, Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<CapabilityMessage>,
    pub port: u16,
    pub id: primitive_types::H512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMessage {
    pub name: CapabilityName,
    pub version: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityName(pub ArrayString<[u8; 4]>);

impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);
        s.append(&self.id);
    }
}

impl Decodable for CapabilityMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

impl Encodable for CapabilityMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl rlp::Decodable for CapabilityName {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self(
            ArrayString::from(
                std::str::from_utf8(rlp.data()?)
                    .map_err(|_| DecoderError::Custom("should be a UTF-8 string"))?,
            )
            .map_err(|_| DecoderError::RlpIsTooBig)?,
        ))
    }
}

impl rlp::Encodable for CapabilityName {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.as_bytes().rlp_append(s);
    }
}


#[derive(Serialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Hash(#[serde(with = "hex::serde")] pub Vec<u8>);

#[derive(Serialize, Clone, Debug)]       
pub struct AccessList(pub Vec<(Hash, Vec<Hash>)>);

#[derive(Clone, Debug)]
pub struct Transaction {
    pub chain_id: Option<u64>,
    pub nonce: u32,
    pub gas_price: Option<BigUint>, // Only present in legacy and type1 transactions
    pub max_priority_fee_per_gas: Option<u64>, // Introduce in type 2 transactions
    pub max_fee_per_gas: Option<u64>, // Introduce in type 2 transactions
    pub gas_limit: u64,
    pub to: Vec<u8>,
    pub value: BigUint,
    pub data: Vec<u8>,
    pub access_list: Option<AccessList>, // Introduce in type 2 transactions
    pub max_fee_per_blob_gas: Option<u32>, // Introduce in type 3 transactions
    pub blob_versioned_hashes: Option<Vec<Hash>>, // Introduce in type 3 transactions
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    // extra info deducted from transaction
    pub txid: Vec<u8>,
    pub from: Vec<u8>,
    pub tx_type: u8,
}

// impl Transaction {
//     pub fn digest(&self) -> Vec<u8> {
//         let msg: Vec<u8> = match &self.tx {
//             Tx::TransactionLegacy(t) => { 
//                 let d = rlp::Rlp::new(&self.raw);
//                 assert!(d.is_list());

//                 let mut s = rlp::RlpStream::new();
//                 s.begin_unbounded_list();
//                 for n in 0..=5 {
//                     s.append_raw(d.at(n).unwrap().as_raw(), 1);
//                 }
//                 if t.v > 28 {
//                     let chain_id = t.v / 2;

//                     s.append(&chain_id);
//                     s.append(&0_u8);
//                     s.append(&0_u8);
//                 }
//                 s.finalize_unbounded_list();

//                 s.as_raw().to_vec()
//             },
//             Tx::TransactionType1(_) => {
//                 let d = rlp::Rlp::new(&self.raw[1..]);
//                 assert!(d.is_list());

//                 let mut s = rlp::RlpStream::new();
//                 s.begin_unbounded_list();
//                 for n in 0..=7 {
//                     s.append_raw(d.at(n).unwrap().as_raw(), 1);
//                 }
//                 s.finalize_unbounded_list();

//                 [&[0x01u8], s.as_raw()].concat()
//             },
//             Tx::TransactionType2(_) => {
//                 let d = rlp::Rlp::new(&self.raw[1..]);
//                 assert!(d.is_list());

//                 let mut s = rlp::RlpStream::new();
//                 s.begin_unbounded_list();
//                 for n in 0..=8 {
//                     s.append_raw(d.at(n).unwrap().as_raw(), 1);
//                 }
//                 s.finalize_unbounded_list();

//                 [&[0x02u8], s.as_raw()].concat()
//             },
//             Tx::TransactionType3(_) => {
//                 let d = rlp::Rlp::new(&self.raw[1..]);
//                 assert!(d.is_list());

//                 let mut s = rlp::RlpStream::new();
//                 s.begin_unbounded_list();
//                 for n in 0..=10 {
//                     s.append_raw(d.at(n).unwrap().as_raw(), 1);
//                 }
//                 s.finalize_unbounded_list();

//                 [&[0x03u8], s.as_raw()].concat()
//             },
//         };

//         let mut hasher = Keccak256::new();
//         hasher.update(&msg);
        
//         hasher.finalize().to_vec()
//     }

//     pub fn get_sig(&self) -> Vec<u8> {
//         let mut r: Vec<u8> = vec![0;32];
//         let mut s: Vec<u8> = vec![0;32];

//         // We need to pas with 00
//         r[(32 - self.tx.r().len())..].copy_from_slice(self.tx.r());
//         s[(32 - self.tx.s().len())..].copy_from_slice(self.tx.s());
//         [r, s].concat().to_vec()
//     }
// }

// We might want more data later
#[derive(Clone, Debug)]
pub struct Block {
    pub number: u32,
    pub hash: Vec<u8>,
    pub parenthash: Vec<u8>,
    pub extradata: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::HelloMessage;
    use crate::message;

    #[test]
    fn test_rlp_hello_message() {
        let payload = hex::decode("f89d05b2476574682f76312e31302e32352d737461626c652d36393536386335352f6c696e75782d616d6436342f676f312e31382e35e5c58365746842c58365746843c5836c657302c5836c657303c5836c657304c684736e61700180b840b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6").unwrap();
        let _hello_message = rlp::decode::<HelloMessage>(&payload);
    }
}
