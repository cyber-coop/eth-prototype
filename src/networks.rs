use std::error::Error;

// Networks
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub genesis_hash: [u8; 32],
    pub head_td: u64,
    pub fork_id: [u32; 2],
    pub network_id: u64,
    /// Fork hashes accepted from peers: the current one (plus the next one around
    /// a hard fork). Peers still syncing or on another chain announce a different
    /// hash and are rejected. Must be updated at every fork. Empty skips the check.
    pub accepted_fork_hashes: &'static [u32],
    /// EIP-1459 DNS tree listing peers for this network, if one is published.
    pub dns_tree: Option<&'static str>,
    /// discv4 bootnodes. Empty disables discv4 for this network.
    pub bootnodes: &'static [&'static str],
}

impl Network {
    // Ethereum Rospten
    pub const ETHEREUM_ROPSTEN: Network = Network {
        genesis_hash: [
            65, 148, 16, 35, 104, 9, 35, 224, 254, 77, 116, 163, 75, 218, 200, 20, 31, 37, 64, 227,
            174, 144, 98, 55, 24, 228, 125, 102, 209, 202, 74, 45,
        ],
        head_td: 50000820485795157,
        fork_id: [0x7119b6b3, 0],
        network_id: 0x03,
        accepted_fork_hashes: &[],
        dns_tree: None,
        bootnodes: &[],
    };

    // Ethereum Rinkeby
    pub const ETHEREUM_RINKEBY: Network = Network {
        genesis_hash: [
            99, 65, 253, 61, 175, 148, 183, 72, 199, 44, 237, 90, 91, 38, 2, 143, 36, 116, 245,
            240, 13, 130, 69, 4, 228, 250, 55, 167, 87, 103, 225, 119,
        ],
        head_td: 20304096,
        fork_id: [0x8e29f2f3, 0],
        network_id: 0x04,
        accepted_fork_hashes: &[],
        dns_tree: None,
        bootnodes: &[],
    };

    // Ethereum Goerli
    pub const ETHEREUM_GOERLI: Network = Network {
        genesis_hash: [
            191, 126, 51, 31, 127, 124, 29, 210, 224, 81, 89, 102, 107, 59, 248, 188, 122, 138, 58,
            158, 177, 213, 24, 150, 158, 171, 82, 157, 217, 184, 140, 26,
        ],
        head_td: 10790000,
        fork_id: [0x70cc14e2, 0],
        network_id: 0x05,
        accepted_fork_hashes: &[],
        dns_tree: None,
        bootnodes: &[],
    };

    // Ethereum Sepolia
    pub const ETHEREUM_SEPOLIA: Network = Network {
        genesis_hash: [
            37, 165, 204, 16, 110, 234, 113, 56, 172, 171, 51, 35, 29, 113, 96, 214, 156, 183, 119,
            238, 12, 44, 85, 63, 205, 223, 81, 56, 153, 62, 109, 217,
        ],
        head_td: 0,
        fork_id: [0xed88b5fd, 0],
        network_id: 0xaa36a7,
        accepted_fork_hashes: &[],
        dns_tree: Some("all.sepolia.ethdisco.net"),
        bootnodes: &[],
    };

    // Ethereum Holesky
    pub const ETHEREUM_HOLESKY: Network = Network {
        genesis_hash: [
            181, 247, 249, 18, 68, 60, 148, 15, 33, 253, 97, 31, 18, 130, 141, 117, 181, 52, 54,
            78, 217, 233, 92, 164, 227, 7, 114, 154, 70, 97, 189, 228,
        ],
        head_td: 1,
        fork_id: [0xdfbd9bed, 0],
        network_id: 0x4268,
        accepted_fork_hashes: &[],
        dns_tree: Some("all.holesky.ethdisco.net"),
        bootnodes: &[],
    };

    // Ethereum Hoodi
    pub const ETHEREUM_HOODI: Network = Network {
        genesis_hash: [
            187, 227, 18, 134, 139, 55, 106, 48, 1, 105, 42, 100, 109, 210, 215, 209, 228, 64, 99,
            128, 223, 216, 107, 152, 170, 138, 52, 209, 85, 124, 151, 27,
        ],
        head_td: 0,
        fork_id: [0x23aa1351, 0],
        network_id: 0x88bb0,
        accepted_fork_hashes: &[],
        dns_tree: Some("all.hoodi.ethdisco.net"),
        bootnodes: &[],
    };

    // Ethereum Mainnet
    pub const ETHEREUM_MAINNET: Network = Network {
        genesis_hash: [
            212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161,
            24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
        ],
        head_td: 0,
        // Frontier hash + Homestead block: every mainnet node accepts it as a peer
        // still syncing, so it keeps working across hard forks (same as Puddle).
        fork_id: [0xfc64ec04, 1150000],
        network_id: 1,
        accepted_fork_hashes: &[0x07c9462e],
        dns_tree: Some("all.mainnet.ethdisco.net"),
        bootnodes: ETHEREUM_BOOTNODES,
    };

    // Binance Mainnet
    pub const BINANCE_MAINNET: Network = Network {
        genesis_hash: [
            13, 33, 132, 10, 191, 244, 107, 150, 200, 75, 42, 201, 225, 14, 79, 92, 218, 235, 86,
            147, 203, 102, 93, 182, 42, 47, 59, 2, 210, 213, 123, 91,
        ],
        head_td: 585970,
        // Fork id reported by most live BSC peers (2026-09-22, from Puddle).
        fork_id: [0xd38cc282, 0],
        network_id: 0x38,
        accepted_fork_hashes: &[],
        dns_tree: None,
        bootnodes: BINANCE_BOOTNODES,
    };

    // Polygon Mainnet
    pub const POLYGON_MAINNET: Network = Network {
        genesis_hash: [
            169, 194, 140, 226, 20, 27, 86, 196, 116, 241, 220, 80, 75, 238, 155, 1, 235, 27, 215,
            209, 165, 7, 88, 13, 85, 25, 212, 67, 122, 151, 222, 27,
        ],
        head_td: 0,
        fork_id: [0x22d523b2, 0],
        network_id: 0x89,
        accepted_fork_hashes: &[],
        dns_tree: Some("pos.polygon-peers.io"),
        bootnodes: POLYGON_BOOTNODES,
    };

    // Base Mainnet
    pub const BASE_MAINNET: Network = Network {
        genesis_hash: [
            247, 18, 170, 146, 65, 204, 36, 54, 155, 20, 60, 246, 220, 232, 95, 9, 2, 169, 115, 30,
            112, 214, 104, 24, 163, 165, 132, 91, 41, 108, 115, 221,
        ],
        head_td: 0,
        fork_id: [0x1cfeafc9, 0],
        network_id: 0x2105,
        accepted_fork_hashes: &[],
        dns_tree: None,
        bootnodes: &[],
    };

    pub fn find(network: &str) -> Result<Self, Box<dyn Error>> {
        match network {
            "ethereum_ropsten" => Ok(Self::ETHEREUM_ROPSTEN),
            "ethereum_rinkeby" => Ok(Self::ETHEREUM_RINKEBY),
            "ethereum_goerli" => Ok(Self::ETHEREUM_GOERLI),
            "ethereum_sepolia" => Ok(Self::ETHEREUM_SEPOLIA),
            "ethereum_holesky" => Ok(Self::ETHEREUM_HOLESKY),
            "ethereum_hoodi" => Ok(Self::ETHEREUM_HOODI),
            "ethereum_mainnet" => Ok(Self::ETHEREUM_MAINNET),
            "binance_mainnet" => Ok(Self::BINANCE_MAINNET),
            "polygon_mainnet" => Ok(Self::POLYGON_MAINNET),
            "base_mainnet" => Ok(Self::BASE_MAINNET),
            _ => Err("not matching available networks.".into()),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            &Self::ETHEREUM_ROPSTEN => "ethereum_ropsten",
            &Self::ETHEREUM_RINKEBY => "ethereum_rinkeby",
            &Self::ETHEREUM_GOERLI => "ethereum_goerli",
            &Self::ETHEREUM_SEPOLIA => "ethereum_sepolia",
            &Self::ETHEREUM_HOLESKY => "ethereum_holesky",
            &Self::ETHEREUM_HOODI => "ethereum_hoodi",
            &Self::ETHEREUM_MAINNET => "ethereum_mainnet",
            &Self::BINANCE_MAINNET => "binance_mainnet",
            &Self::POLYGON_MAINNET => "polygon_mainnet",
            &Self::BASE_MAINNET => "base_mainnet",
            _ => panic!("Unknown network"),
        }
        .to_string()
    }
}

// Bootnode lists copied from Puddle.
pub const BINANCE_BOOTNODES: &[&str] = &[
    "enode://433c8bfdf53a3e2268ccb1b829e47f629793291cbddf0c76ae626da802f90532251fc558e2e0d10d6725e759088439bf1cd4714716b03a259a35d4b2e4acfa7f@52.69.102.73:30311",
    "enode://571bee8fb902a625942f10a770ccf727ae2ba1bab2a2b64e121594a99c9437317f6166a395670a00b7d93647eacafe598b6bbcef15b40b6d1a10243865a3e80f@35.73.84.120:30311",
    "enode://fac42fb0ba082b7d1eebded216db42161163d42e4f52c9e47716946d64468a62da4ba0b1cac0df5e8bf1e5284861d757339751c33d51dfef318be5168803d0b5@18.203.152.54:30311",
    "enode://3063d1c9e1b824cfbb7c7b6abafa34faec6bb4e7e06941d218d760acdd7963b274278c5c3e63914bd6d1b58504c59ec5522c56f883baceb8538674b92da48a96@34.250.32.100:30311",
    "enode://ad78c64a4ade83692488aa42e4c94084516e555d3f340d9802c2bf106a3df8868bc46eae083d2de4018f40e8d9a9952c32a0943cd68855a9bc9fd07aac982a6d@34.204.214.24:30311",
    "enode://5db798deb67df75d073f8e2953dad283148133acb520625ea804c9c4ad09a35f13592a762d8f89056248f3889f6dcc33490c145774ea4ff2966982294909b37a@107.20.191.97:30311",
];

// Source: 0xPolygon/bor params/bootnodes.go (BorMainnetBootnodes).
pub const POLYGON_BOOTNODES: &[&str] = &[
    "enode://e4fb013061eba9a2c6fb0a41bbd4149f4808f0fb7e88ec55d7163f19a6f02d64d0ce5ecc81528b769ba552a7068057432d44ab5e9e42842aff5b4709aa2c3f3b@34.89.75.187:30303",
    "enode://a49da6300403cf9b31e30502eb22c142ba4f77c9dda44990bccce9f2121c3152487ee95ee55c6b92d4cdce77845e40f59fd927da70ea91cf935b23e262236d75@34.142.43.249:30303",
];

pub const ETHEREUM_BOOTNODES: &[&str] = &[
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303", // bootnode-aws-ap-southeast-1-001
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303", // bootnode-aws-us-east-1-001
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303", // bootnode-hetzner-hel
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303", // bootnode-hetzner-fsn
];
