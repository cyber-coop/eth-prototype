use arrayvec::ArrayString;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

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

#[derive(Clone, Debug)]
pub struct Transaction {
    pub txid: Vec<u8>,
    pub nonce: u32,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub to: Vec<u8>,
    // value is Bigint not u64 (https://github.com/ethereum/go-ethereum/blob/master/core/types/tx_legacy.go#L31)
    // lets save it as raw bytes
    pub value: Vec<u8>,
    pub data: Vec<u8>,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub raw: Vec<u8>,
}

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

    #[test]
    fn test_rlp_hello_message() {
        let payload = hex::decode("f89d05b2476574682f76312e31302e32352d737461626c652d36393536386335352f6c696e75782d616d6436342f676f312e31382e35e5c58365746842c58365746843c5836c657302c5836c657303c5836c657304c684736e61700180b840b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6").unwrap();
        let _hello_message = rlp::decode::<HelloMessage>(&payload);
    }
}
