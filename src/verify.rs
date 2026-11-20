//! Checks on data received from peers. Peers are untrusted: anything they send
//! must be validated before it reaches the database.

use sha3::{Digest, Keccak256};

use crate::types::Block;

/// Root of an empty Merkle-Patricia trie: keccak256(rlp("")).
pub const EMPTY_TRIE_ROOT: [u8; 32] =
    hex_literal(b"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

/// Hash of an empty ommers list: keccak256(rlp([])).
pub const EMPTY_OMMERS_HASH: [u8; 32] =
    hex_literal(b"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

const fn hex_literal(hex: &[u8; 64]) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Roots computed locally from the raw RLP of a block body, to be compared with
/// the values committed in the block header.
#[derive(Clone, Debug)]
pub struct BodyRoots {
    pub txs_root: [u8; 32],
    pub ommers_hash: [u8; 32],
    /// `None` when the body has no withdrawals list (pre-Shanghai).
    pub withdrawals_root: Option<[u8; 32]>,
}

impl BodyRoots {
    /// `txs` are the trie values of the transactions: the RLP list for legacy
    /// transactions, `type || payload` for typed ones. `ommers_rlp` is the raw
    /// RLP of the ommers list, `withdrawals` the raw RLP of each withdrawal.
    pub fn compute<T: AsRef<[u8]>, W: AsRef<[u8]>>(
        txs: &[T],
        ommers_rlp: &[u8],
        withdrawals: Option<&[W]>,
    ) -> Self {
        BodyRoots {
            txs_root: ordered_trie_root(txs),
            ommers_hash: keccak(ommers_rlp),
            withdrawals_root: withdrawals.map(ordered_trie_root),
        }
    }
}

/// Root of the trie mapping `rlp(index)` to `values[index]`, as used for the
/// transactions, receipts and withdrawals roots.
pub fn ordered_trie_root<V: AsRef<[u8]>>(values: &[V]) -> [u8; 32] {
    let items: Vec<(Vec<u8>, &[u8])> = values
        .iter()
        .enumerate()
        .map(|(i, v)| (to_nibbles(&rlp::encode(&i)), v.as_ref()))
        .collect();
    trie_root(&items.iter().collect::<Vec<_>>())
}

/// Root of a trie built from (key nibbles, value) pairs. Keys must be unique.
fn trie_root(items: &[&(Vec<u8>, &[u8])]) -> [u8; 32] {
    if items.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    keccak(&encode_node(items, 0))
}

fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix encoding of a nibble path (Yellow Paper, appendix C).
fn hex_prefix(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 } + (nibbles.len() % 2) as u8;
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
    let rest = if nibbles.len() % 2 == 1 {
        out.push((flag << 4) | nibbles[0]);
        &nibbles[1..]
    } else {
        out.push(flag << 4);
        nibbles
    };
    out.extend(rest.chunks(2).map(|p| (p[0] << 4) | p[1]));
    out
}

/// Appends a reference to a child node: inlined if its encoding is shorter
/// than 32 bytes, otherwise its hash.
fn append_child(stream: &mut rlp::RlpStream, encoded: &[u8]) {
    if encoded.len() < 32 {
        stream.append_raw(encoded, 1);
    } else {
        stream.append(&keccak(encoded).as_slice());
    }
}

/// RLP encoding of the node holding `items`, whose keys all share the first
/// `depth` nibbles.
fn encode_node(items: &[&(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new();

    if let [(key, value)] = items {
        // Leaf
        stream.begin_list(2);
        stream.append(&hex_prefix(&key[depth..], true));
        stream.append(value);
        return stream.out().to_vec();
    }

    // Longest prefix shared by every key from `depth` on.
    let first = &items[0].0;
    let mut end = depth;
    while items
        .iter()
        .all(|(key, _)| key.len() > end && key[end] == first[end])
    {
        end += 1;
    }

    if end > depth {
        // Extension
        stream.begin_list(2);
        stream.append(&hex_prefix(&first[depth..end], false));
        append_child(&mut stream, &encode_node(items, end));
        return stream.out().to_vec();
    }

    // Branch: one slot per nibble, plus the value of a key ending here.
    stream.begin_list(17);
    for nibble in 0..16u8 {
        let children: Vec<_> = items
            .iter()
            .copied()
            .filter(|(key, _)| key.len() > depth && key[depth] == nibble)
            .collect();
        if children.is_empty() {
            stream.append_empty_data();
        } else {
            append_child(&mut stream, &encode_node(&children, depth + 1));
        }
    }
    match items.iter().find(|(key, _)| key.len() == depth) {
        Some((_, value)) => stream.append(value),
        None => stream.append_empty_data(),
    };
    stream.out().to_vec()
}

/// Adds `data` to a 2048-bit logs bloom filter (Yellow Paper, section 4.3.1):
/// three bits, each taken from a pair of bytes of keccak256(data).
fn bloom_add(bloom: &mut [u8; 256], data: &[u8]) {
    let hash = keccak(data);
    for i in 0..3 {
        let bit = (((hash[2 * i] as usize) << 8) | hash[2 * i + 1] as usize) & 2047;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

/// Logs bloom of a receipt, from the RLP list of its logs
/// (each log is `[address, [topics...], data]`).
pub fn logs_bloom(logs: &rlp::Rlp) -> Result<[u8; 256], rlp::DecoderError> {
    let mut bloom = [0u8; 256];
    for log in logs.iter() {
        bloom_add(&mut bloom, log.at(0)?.data()?);
        for topic in log.at(1)?.iter() {
            bloom_add(&mut bloom, topic.data()?);
        }
    }
    Ok(bloom)
}

/// Value stored in the receipts trie for an eth69 receipt.
///
/// eth69 sends receipts as `[tx_type, status, cumulative_gas, logs, ...]`
/// without the bloom. The consensus encoding is
/// `rlp([status, cumulative_gas, bloom, logs, ...])`, prefixed by the type byte
/// for typed transactions. Fields after `logs` (e.g. OP-stack deposit receipts'
/// `depositNonce` and `depositReceiptVersion`) are kept as they are.
pub fn eth69_receipt_trie_value(receipt: &rlp::Rlp) -> Result<Vec<u8>, rlp::DecoderError> {
    let count = receipt.item_count()?;
    if count < 4 {
        return Err(rlp::DecoderError::RlpIncorrectListLen);
    }
    let tx_type: u8 = receipt.val_at(0)?;
    let logs = receipt.at(3)?;

    let mut stream = rlp::RlpStream::new_list(count);
    stream.append_raw(receipt.at(1)?.as_raw(), 1);
    stream.append_raw(receipt.at(2)?.as_raw(), 1);
    stream.append(&logs_bloom(&logs)?.as_slice());
    stream.append_raw(logs.as_raw(), 1);
    for i in 4..count {
        stream.append_raw(receipt.at(i)?.as_raw(), 1);
    }

    let encoded = stream.out();
    Ok(if tx_type == 0 {
        encoded.to_vec()
    } else {
        [&[tx_type][..], &encoded].concat()
    })
}

/// Checks a `Receipts` response against the headers it was requested for.
/// `roots` are the receipts roots computed for each block, in request order.
pub fn verify_receipts(headers: &[Block], roots: &[[u8; 32]]) -> Result<(), String> {
    if roots.len() > headers.len() {
        return Err(format!(
            "received receipts for {} blocks but asked for {}",
            roots.len(),
            headers.len()
        ));
    }

    for (header, root) in headers.iter().zip(roots) {
        if header.receipts_root != root {
            return Err(format!(
                "block n° {} ({}): receipts root {} does not match header {}",
                header.number,
                hex::encode(&header.hash),
                hex::encode(root),
                hex::encode(&header.receipts_root)
            ));
        }
    }

    Ok(())
}

/// Checks a `BlockBodies` response against the headers it was requested for.
/// Bodies come back in request order, and a peer may return fewer than asked.
pub fn verify_block_bodies(headers: &[Block], roots: &[BodyRoots]) -> Result<(), String> {
    if roots.len() > headers.len() {
        return Err(format!(
            "received {} bodies but asked for {}",
            roots.len(),
            headers.len()
        ));
    }

    for (header, roots) in headers.iter().zip(roots) {
        let block = || format!("block n° {} ({})", header.number, hex::encode(&header.hash));

        if header.txs_root != roots.txs_root {
            return Err(format!(
                "{}: transactions root {} does not match header {}",
                block(),
                hex::encode(roots.txs_root),
                hex::encode(&header.txs_root)
            ));
        }

        if header.ommers_hash != roots.ommers_hash {
            return Err(format!(
                "{}: ommers hash {} does not match header {}",
                block(),
                hex::encode(roots.ommers_hash),
                hex::encode(&header.ommers_hash)
            ));
        }

        // Pre-Shanghai headers have no withdrawals root; the body must then have
        // no withdrawals either.
        let expected = (!header.withdrawals_root.is_empty()).then_some(&header.withdrawals_root);
        match (expected, roots.withdrawals_root) {
            (None, None) => {}
            (None, Some(root)) if root == EMPTY_TRIE_ROOT => {}
            (Some(expected), Some(root)) if *expected == root => {}
            (expected, root) => {
                return Err(format!(
                    "{}: withdrawals root {:?} does not match header {:?}",
                    block(),
                    root.map(hex::encode),
                    expected.map(hex::encode)
                ));
            }
        }
    }

    Ok(())
}

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
    use super::*;

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

    fn root_of(pairs: &[(&[u8], &[u8])]) -> String {
        let items: Vec<(Vec<u8>, &[u8])> = pairs.iter().map(|(k, v)| (to_nibbles(k), *v)).collect();
        hex::encode(trie_root(&items.iter().collect::<Vec<_>>()))
    }

    #[test]
    fn empty_roots() {
        let none: [&[u8]; 0] = [];
        assert_eq!(ordered_trie_root(&none), EMPTY_TRIE_ROOT);
        assert_eq!(keccak(&rlp::encode(&"")), EMPTY_TRIE_ROOT);
        assert_eq!(keccak(&[0xc0]), EMPTY_OMMERS_HASH);
    }

    // Vectors from ethereum/tests TrieTests (trieanyorder.json).
    #[test]
    fn trie_single_item() {
        let value = [b'a'; 50];
        assert_eq!(
            root_of(&[(b"A", &value)]),
            "d23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab"
        );
    }

    #[test]
    fn trie_dogs() {
        // Exercises leaves, extensions and a branch holding a value ("do").
        assert_eq!(
            root_of(&[
                (b"doe", b"reindeer"),
                (b"dog", b"puppy"),
                (b"dogglesworth", b"cat"),
            ]),
            "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"
        );
        assert_eq!(
            root_of(&[
                (b"do", b"verb"),
                (b"horse", b"stallion"),
                (b"doge", b"coin"),
                (b"dog", b"puppy"),
            ]),
            "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"
        );
    }

    #[test]
    fn trie_root_independent_of_insert_order() {
        let a = root_of(&[(b"abc", b"1"), (b"abd", b"2"), (b"x", b"3")]);
        let b = root_of(&[(b"x", b"3"), (b"abd", b"2"), (b"abc", b"1")]);
        assert_eq!(a, b);
    }

    #[test]
    fn hex_prefix_encoding() {
        // Yellow Paper appendix C examples.
        assert_eq!(hex_prefix(&[1, 2, 3, 4, 5], false), vec![0x11, 0x23, 0x45]);
        assert_eq!(
            hex_prefix(&[0, 1, 2, 3, 4, 5], false),
            vec![0x00, 0x01, 0x23, 0x45]
        );
        assert_eq!(
            hex_prefix(&[0, 15, 1, 12, 11, 8], true),
            vec![0x20, 0x0f, 0x1c, 0xb8]
        );
        assert_eq!(
            hex_prefix(&[15, 1, 12, 11, 8], true),
            vec![0x3f, 0x1c, 0xb8]
        );
    }

    fn header_with_roots(txs_root: [u8; 32], withdrawals_root: Vec<u8>) -> Block {
        let mut h = header(1, 0x01, 0x00);
        h.txs_root = txs_root.to_vec();
        h.ommers_hash = EMPTY_OMMERS_HASH.to_vec();
        h.withdrawals_root = withdrawals_root;
        h
    }

    #[test]
    fn verifies_body_roots() {
        let txs = [vec![0xc1, 0x01], vec![0x02, 0xc1, 0x02]];
        let wds = [vec![0xc1, 0x03]];
        let roots = BodyRoots::compute(&txs, &[0xc0], Some(&wds[..]));
        let header = header_with_roots(roots.txs_root, ordered_trie_root(&wds).to_vec());
        assert!(verify_block_bodies(&[header.clone()], &[roots.clone()]).is_ok());

        // Tampered transaction list
        let bad = BodyRoots::compute(&txs[..1], &[0xc0], Some(&wds[..]));
        assert!(verify_block_bodies(&[header.clone()], &[bad]).is_err());

        // Missing withdrawals after Shanghai
        let no_wd = BodyRoots::compute::<_, Vec<u8>>(&txs, &[0xc0], None);
        assert!(verify_block_bodies(&[header.clone()], &[no_wd]).is_err());

        // More bodies than requested
        assert!(verify_block_bodies(&[header], &[roots.clone(), roots]).is_err());
    }

    #[test]
    fn verifies_pre_shanghai_body() {
        let txs: [Vec<u8>; 0] = [];
        let roots = BodyRoots::compute::<_, Vec<u8>>(&txs, &[0xc0], None);
        let header = header_with_roots(EMPTY_TRIE_ROOT, vec![]);
        assert!(verify_block_bodies(&[header.clone()], &[roots]).is_ok());

        let with_wd = BodyRoots::compute(&txs, &[0xc0], Some(&[vec![0xc1, 0x03]][..]));
        assert!(verify_block_bodies(&[header], &[with_wd]).is_err());
    }

    // eth69 receipt: [tx_type, status, cumulative_gas, logs, extra...]
    fn eth69_receipt(
        tx_type: u8,
        logs: &[(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)],
        extra: &[u64],
    ) -> Vec<u8> {
        let mut s = rlp::RlpStream::new_list(4 + extra.len());
        s.append(&tx_type);
        s.append(&1u8);
        s.append(&21000u64);
        s.begin_list(logs.len());
        for (address, topics, data) in logs {
            s.begin_list(3);
            s.append(address);
            s.append_list::<Vec<u8>, Vec<u8>>(topics);
            s.append(data);
        }
        for e in extra {
            s.append(e);
        }
        s.out().to_vec()
    }

    fn one_log() -> Vec<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> {
        vec![(
            vec![0x11; 20],
            vec![vec![0x22; 32], vec![0x33; 32]],
            vec![0xde, 0xad],
        )]
    }

    #[test]
    fn bloom_sets_at_most_three_bits_per_item() {
        let mut bloom = [0u8; 256];
        bloom_add(&mut bloom, b"hello");
        let bits: u32 = bloom.iter().map(|b| b.count_ones()).sum();
        assert!((1..=3).contains(&bits));

        let before = bloom;
        bloom_add(&mut bloom, b"hello");
        assert_eq!(before, bloom);
    }

    #[test]
    fn logs_bloom_covers_address_and_topics() {
        let raw = eth69_receipt(2, &one_log(), &[]);
        let receipt = rlp::Rlp::new(&raw);
        let bloom = logs_bloom(&receipt.at(3).unwrap()).unwrap();

        let mut expected = [0u8; 256];
        bloom_add(&mut expected, &[0x11; 20]);
        bloom_add(&mut expected, &[0x22; 32]);
        bloom_add(&mut expected, &[0x33; 32]);
        assert_eq!(bloom, expected);

        let empty = eth69_receipt(0, &[], &[]);
        assert_eq!(
            logs_bloom(&rlp::Rlp::new(&empty).at(3).unwrap()).unwrap(),
            [0u8; 256]
        );
    }

    fn consensus_receipt(logs: &[(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)], extra: &[u64]) -> Vec<u8> {
        let raw = eth69_receipt(0, logs, &[]);
        let bloom = logs_bloom(&rlp::Rlp::new(&raw).at(3).unwrap()).unwrap();
        let mut s = rlp::RlpStream::new_list(4 + extra.len());
        s.append(&1u8);
        s.append(&21000u64);
        s.append(&bloom.as_slice());
        s.append_raw(rlp::Rlp::new(&raw).at(3).unwrap().as_raw(), 1);
        for e in extra {
            s.append(e);
        }
        s.out().to_vec()
    }

    #[test]
    fn receipt_trie_value_legacy() {
        let raw = eth69_receipt(0, &one_log(), &[]);
        let value = eth69_receipt_trie_value(&rlp::Rlp::new(&raw)).unwrap();
        assert_eq!(value, consensus_receipt(&one_log(), &[]));
    }

    #[test]
    fn receipt_trie_value_typed() {
        let raw = eth69_receipt(2, &one_log(), &[]);
        let value = eth69_receipt_trie_value(&rlp::Rlp::new(&raw)).unwrap();
        assert_eq!(value[0], 0x02);
        assert_eq!(&value[1..], consensus_receipt(&one_log(), &[]));
    }

    #[test]
    fn receipt_trie_value_keeps_extra_fields() {
        // OP-stack deposit receipt: depositNonce and depositReceiptVersion after logs.
        let raw = eth69_receipt(0x7e, &[], &[42, 1]);
        let value = eth69_receipt_trie_value(&rlp::Rlp::new(&raw)).unwrap();
        assert_eq!(value[0], 0x7e);
        assert_eq!(&value[1..], consensus_receipt(&[], &[42, 1]));
    }

    #[test]
    fn receipt_trie_value_rejects_short_list() {
        let mut s = rlp::RlpStream::new_list(3);
        s.append(&0u8).append(&1u8).append(&21000u64);
        assert!(eth69_receipt_trie_value(&rlp::Rlp::new(&s.out())).is_err());
    }

    #[test]
    fn verifies_receipts_root() {
        let values = [
            eth69_receipt_trie_value(&rlp::Rlp::new(&eth69_receipt(2, &one_log(), &[]))).unwrap(),
        ];
        let root = ordered_trie_root(&values);
        let mut h = header(1, 0x01, 0x00);
        h.receipts_root = root.to_vec();

        assert!(verify_receipts(&[h.clone()], &[root]).is_ok());
        assert!(verify_receipts(&[h.clone()], &[EMPTY_TRIE_ROOT]).is_err());
        assert!(verify_receipts(&[h], &[root, root]).is_err());
    }
}
