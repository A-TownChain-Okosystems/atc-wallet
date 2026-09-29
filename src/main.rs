use atc_wallet_core::keys::WalletKey;
use atc_wallet_core::tx::Transaction;

fn main() {
    let key = WalletKey::from_seed([0u8; 32]);
    println!("atc-wallet");
    println!("public_key={:?}", key.public_key());
    let _ = std::mem::size_of::<Transaction>();
}
