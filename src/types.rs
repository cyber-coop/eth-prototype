use num::BigUint;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::Serialize;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityName(pub String);

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
        Ok(Self(rlp.as_val()?))
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
    pub max_fee_per_blob_gas: Option<u64>, // Introduce in type 3 transactions
    pub blob_versioned_hashes: Option<Vec<Hash>>, // Introduce in type 3 transactions
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    // extra info deducted from transaction
    pub txid: Vec<u8>,
    pub from: Vec<u8>,
    pub tx_type: u8,
}

// We might want more data later
// TODO: Instead of Vec, use byte array with defined length (example: [u8;32])
#[derive(Clone, Debug)]
pub struct Block {
    pub hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub ommers_hash: Vec<u8>,
    pub coinbase: Vec<u8>,
    pub state_root: Vec<u8>,
    pub txs_root: Vec<u8>,
    pub receipts_root: Vec<u8>,
    pub bloom: Vec<u8>,
    pub difficulty: u64,
    pub number: u32,
    pub gas_limit: u32,
    pub gas_used: u32,
    pub time: u32,
    pub extradata: Vec<u8>,
    pub mix_digest: Vec<u8>,
    pub block_nonce: Vec<u8>,
    pub basefee_per_gas: u64,
    pub withdrawals_root: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: Vec<u8>,
    pub amount: u64,
}

#[cfg(test)]
mod tests {
    use super::HelloMessage;

    #[test]
    fn test_rlp_hello_message() {
        let payload = hex::decode("f89d05b2476574682f76312e31302e32352d737461626c652d36393536386335352f6c696e75782d616d6436342f676f312e31382e35e5c58365746842c58365746843c5836c657302c5836c657303c5836c657304c684736e61700180b840b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6").unwrap();
        let _hello_message = rlp::decode::<HelloMessage>(&payload);
    }
}
