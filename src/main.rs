use atc_wallet_core::keys::WalletKey;
use atc_wallet_core::tx::Transaction;

fn main() {
    let key = WalletKey::from_private_key_bytes(&[0u8; 32]).expect("valid private key");
    println!("atc-wallet");
    println!("public_key={:?}", key.public_key());
    let _ = std::mem::size_of::<Transaction>();
}
