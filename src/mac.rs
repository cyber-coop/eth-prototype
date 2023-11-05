use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit};
use sha3::{Keccak256, Digest};

pub struct MAC {
    hash: Keccak256,
    secret: Vec<u8>,
}

type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;

impl MAC {
    pub fn new(secret: Vec<u8>) -> Self {
        let hash = Keccak256::new();

        return MAC{ hash, secret };
    }

    pub fn update(&mut self, data: &Vec<u8>) {
        self.hash.update(data);
    }

    pub fn update_header(&mut self, data: &mut Vec<u8>) {
        let aes = Aes256EcbEnc::new(self.secret.as_slice().into());
        let mut block = self.digest();
        let encrypted = aes.encrypt_padded_mut::<NoPadding>(block.as_mut(), 16).unwrap();

        let xor_result: Vec<u8> = encrypted
            .iter()
            .zip(data.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        self.hash.update(xor_result);
    }

    pub fn update_body(&mut self, data: &mut Vec<u8>) {
        self.hash.update(data);
        let prev = self.digest();

        let aes = Aes256EcbEnc::new(self.secret.as_slice().into());
        let mut block = prev.clone();
        let encrypted = aes.encrypt_padded_mut::<NoPadding>(block.as_mut(), 16).unwrap();

        let xor_result: Vec<u8> = encrypted
            .iter()
            .zip(prev.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        self.hash.update(xor_result)
    }

    pub fn digest(&self) -> Vec<u8> {
        return self.hash.clone().finalize()[0..16].to_vec();
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::MAC;
    use sha3::Keccak256;
    use sha3::Digest;

    #[test]
    fn test_update_header() {
        let secret = hex::decode("128041d7ebcbdcb728bf5c4fc5cd82ec46e789b9bbfab8a38cb81f7dd34a0c4c").unwrap();
        let mut ingress_mac = MAC::new(secret);

        let data = hex::decode("a774ca295367bb1503092692163b6ebb43b649cb37ca50ff2d480c2d4e42c75f016c04c62f45dec8dc83989e74f6a0795bae2efe2f04f58f5ee0d62d3beec7b8bc1cf1cbbb3b2df89389b0fb8cb46672374ff63fbb8e6f894618f63cb4b4a80de9f11a6f99d3015abbbbccf802b5e947f36f30a59525e98c59f599120a5cf0a8a03d551ba79fe4e477c5b184c9b9069378da2a4a58cdceeb8fab379674df69144afa5dc07092e7ed24ff295872df2014399c20b9add0fc2b82a3996fb001b4e67bda456a5e21166cd5529c047ff52c8847bdf1e32d695b8c026f16660d52a662f3de35ae86b8b038229f65421a2174e79245dc8169d72e8b22ec89304d26edbe73fefdd7291472fc551458a14e0ee66d19de03c9d89124b1e7b76dbd8def0ed028a2d5d5d4757c62e2684d889a82684d4eb0d425a923b47554959c4512bb512cd3d387c48ead968eb7f60c522bf7f3115da1908de3f3ae72fba36c180819aa0523b4a290591926b7a4ebaabf4e2cd227ad16bcaa6632d48702e379ad473a12c7353bf81a5c82b0281eb200684146").unwrap();
        ingress_mac.update(&data);

        let d = ingress_mac.digest();
        assert_eq!(d, hex::decode("d6ac9901fd534b937b8d25aa67d530bd").unwrap());

        let mut header = hex::decode("044d1a9e6283d1158eed2f1d662e52a3").unwrap();
        ingress_mac.update_header(&mut header);

        let _mac = ingress_mac.digest();

        let mac = hex::decode("d1d250c3a2d0547a6975150ba4bb07af").unwrap();
        assert_eq!(_mac, mac);
    }

    #[test]
    fn test_keccak256() {
        let mut hasher = Keccak256::new();
        hasher.update("lola");
        let lola = hasher.finalize();

        assert_eq!(lola.to_vec(), hex::decode("4a043346b8c9f74d7bd8ba9a60e957c6355fed50423278ff175fa6b7fd42d88c").unwrap());
    }
}