use atc_wallet_core::keys::KeyPair;
use atc_wallet_core::tx::Transaction;

fn main() {
    let key = KeyPair::from_seed([0u8; 32]);
    println!("atc-wallet");
    println!("public_key={:?}", key.public_key_bytes());
    let _ = std::mem::size_of::<Transaction>();
}
