//! Checks on data received from peers. Peers are untrusted: anything they send
//! must be validated before it reaches the database.

use crate::types::Block;

/// Checks that a `BlockHeaders` response is a linked chain starting at the
/// requested hash.
///
/// Header hashes are computed locally (keccak of the RLP header) when parsing,
/// so checking the links between them ties every header back to `start_hash`.
///
/// - `reverse = true`: headers go from `start_hash` towards genesis, so each
///   header's `parent_hash` is the next header's hash.
/// - `reverse = false`: headers go from `start_hash` towards the tip, so each
///   header is the parent of the next one.
pub fn verify_header_chain(
    headers: &[Block],
    start_hash: &[u8],
    reverse: bool,
    max_count: usize,
) -> Result<(), String> {
    let Some(first) = headers.first() else {
        return Ok(());
    };

    if headers.len() > max_count {
        return Err(format!(
            "received {} headers but asked for at most {}",
            headers.len(),
            max_count
        ));
    }

    if first.hash != start_hash {
        return Err(format!(
            "first header is {} but we asked for {}",
            hex::encode(&first.hash),
            hex::encode(start_hash)
        ));
    }

    for pair in headers.windows(2) {
        let (parent, child) = if reverse {
            (&pair[1], &pair[0])
        } else {
            (&pair[0], &pair[1])
        };

        if child.parent_hash != parent.hash {
            return Err(format!(
                "header {} (n° {}) does not link to {} (n° {})",
                hex::encode(&child.hash),
                child.number,
                hex::encode(&parent.hash),
                parent.number
            ));
        }

        if parent.number.checked_add(1) != Some(child.number) {
            return Err(format!(
                "header n° {} follows n° {}",
                child.number, parent.number
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_header_chain;
    use crate::types::Block;

    fn header(number: u32, hash: u8, parent: u8) -> Block {
        Block {
            hash: vec![hash; 32],
            parent_hash: vec![parent; 32],
            ommers_hash: vec![],
            coinbase: vec![],
            state_root: vec![],
            txs_root: vec![],
            receipts_root: vec![],
            bloom: vec![],
            difficulty: 0,
            number,
            gas_limit: 0,
            gas_used: 0,
            time: 0,
            extradata: vec![],
            mix_digest: vec![],
            block_nonce: vec![],
            basefee_per_gas: 0,
            withdrawals_root: vec![],
        }
    }

    // Chain: 10 (0x0a) <- 11 (0x0b) <- 12 (0x0c)
    fn chain() -> Vec<Block> {
        vec![
            header(10, 0x0a, 0x09),
            header(11, 0x0b, 0x0a),
            header(12, 0x0c, 0x0b),
        ]
    }

    #[test]
    fn accepts_forward_chain() {
        assert!(verify_header_chain(&chain(), &[0x0a; 32], false, 1024).is_ok());
    }

    #[test]
    fn accepts_reverse_chain() {
        let mut headers = chain();
        headers.reverse();
        assert!(verify_header_chain(&headers, &[0x0c; 32], true, 1024).is_ok());
    }

    #[test]
    fn accepts_empty() {
        assert!(verify_header_chain(&[], &[0x0a; 32], false, 1024).is_ok());
    }

    #[test]
    fn rejects_wrong_start() {
        assert!(verify_header_chain(&chain(), &[0x0b; 32], false, 1024).is_err());
    }

    #[test]
    fn rejects_wrong_direction() {
        assert!(verify_header_chain(&chain(), &[0x0a; 32], true, 1024).is_err());
    }

    #[test]
    fn rejects_broken_link() {
        let mut headers = chain();
        headers[2].parent_hash = vec![0xff; 32];
        assert!(verify_header_chain(&headers, &[0x0a; 32], false, 1024).is_err());
    }

    #[test]
    fn rejects_wrong_number() {
        let mut headers = chain();
        headers[2].number = 13;
        assert!(verify_header_chain(&headers, &[0x0a; 32], false, 1024).is_err());
    }

    #[test]
    fn rejects_too_many() {
        assert!(verify_header_chain(&chain(), &[0x0a; 32], false, 2).is_err());
    }
}
