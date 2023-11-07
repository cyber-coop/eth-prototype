use ethereum_types::H160;
use rlp::{Encodable, RlpStream};
use std::str::FromStr;
use tx_from_scratch::Transaction;
use web3::signing::recover;

fn main() {
    // Construct Transaction
    let tx = Transaction {
        // Nonce of the transaction
        nonce: 0,

        gas_price: 20000000000,
        gas: 21005,

        // To Address
        to: Some(
            H160::from_str("b82875007a206d52222887b8bc21ed309357f878")
                .unwrap()
                .to_fixed_bytes(),
        ),

        // Value
        value: 1000000000000000,

        // Chain ID
        chain_id: 1,

        // Rest is default
        ..Default::default()
    };

    let mut stream = RlpStream::new();
    tx.rlp_append(&mut stream);
    stream.append(&tx.chain_id);
    stream.append_raw(&[0x80], 1);
    stream.append_raw(&[0x80], 1);
    stream.finalize_unbounded_list();
    let rlp_bytes = stream.out().to_vec();

    println!("{}", hex::encode(rlp_bytes));
    println!("{}", hex::encode(tx.hash()));

    let _pubkey = recover(
        &hex::decode("ecd14630af1af41c696f76484ac0f38225bda8fd185ad91036f8941868c9a502").unwrap(),
        &hex::decode("1cb88761e7336a401894aa9e5faf0daa20b2ea3b46266ba349fa3f22a09d44fd7f4696182980f316ac96b9da3bcd89474edf783cc1bab9ee6553e84aa931b8bd").unwrap(),
        27,
    );
}
