use std::error::Error;

// Networks
pub struct Network {
    pub genesis_hash: [u8; 32],
    pub head_td: u64,
    pub fork_id: [u32; 2],
    pub network_id: u32,
}

impl Network {
    // Geth/v1.11.5-stable/linux-amd64/go1.19.5
    pub const ETHEREUM_RINKEBY: Network = Network {
        genesis_hash: [
            99, 65, 253, 61, 175, 148, 183, 72, 199, 44, 237, 90, 91, 38, 2, 143, 36, 116, 245,
            240, 13, 130, 69, 4, 228, 250, 55, 167, 87, 103, 225, 119,
        ],
        head_td: 20139786,
        fork_id: [0x3b8e0691, 1],
        network_id: 0x04,
    };

    // Ethereum Goerli
    pub const ETHEREUM_GOERLI: Network = Network {
        genesis_hash: [
            191, 126, 51, 31, 127, 124, 29, 210, 224, 81, 89, 102, 107, 59, 248, 188, 122, 138, 58,
            158, 177, 213, 24, 150, 158, 171, 82, 157, 217, 184, 140, 26,
        ],
        head_td: 10790000,
        fork_id: [0xf9843abf, 0],
        network_id: 0x05,
    };

    // Ethereum Sepolia
    pub const ETHEREUM_SEPOLIA: Network = Network {
        genesis_hash: [
            37, 165, 204, 16, 110, 234, 113, 56, 172, 171, 51, 35, 29, 113, 96, 214, 156, 183, 119,
            238, 12, 44, 85, 63, 205, 223, 81, 56, 153, 62, 109, 217,
        ],
        head_td: 0x3c656d23029ab0,
        fork_id: [0xf7f9bc08, 0],
        network_id: 0xaa36a7,
    };

    // Ethereum Mainnet
    pub const ETHEREUM_MAINNET: Network = Network {
        genesis_hash: [
            212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161,
            24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
        ],
        head_td: 0,
        fork_id: [0xdce96c2d, 0],
        network_id: 1,
    };

    // Binance Mainnet
    pub const BINANCE_MAINNET: Network = Network {
        genesis_hash: [
            13, 33, 132, 10, 191, 244, 107, 150, 200, 75, 42, 201, 225, 14, 79, 92, 218, 235, 86,
            147, 203, 102, 93, 182, 42, 47, 59, 2, 210, 213, 123, 91,
        ],
        head_td: 5074736,
        fork_id: [0xa6bf97c1, 31302048],
        network_id: 0x38,
    };

    pub fn find(network: &str) -> Result<Self, Box<dyn Error>> {
        match network {
            "ethereum_rinkeby" => Ok(Self::ETHEREUM_RINKEBY),
            "ethereum_goerli" => Ok(Self::ETHEREUM_GOERLI),
            "ethereum_sepolia" => Ok(Self::ETHEREUM_SEPOLIA),
            "ethereum_mainnet" => Ok(Self::ETHEREUM_MAINNET),
            "binance_mainnet" => Ok(Self::BINANCE_MAINNET),
            _ => Err("not matching available networks.".into()),
        }
    }
}
