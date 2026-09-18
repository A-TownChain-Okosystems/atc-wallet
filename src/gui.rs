//! GUI boundary. Wallet state and signing stay in the core modules.

#[derive(Debug, Default)]
pub struct WalletUi {
    pub show_balance: bool,
}

impl WalletUi {
    pub fn new() -> Self { Self { show_balance: true } }
}
