# ATC-Wallet — Wallet Application

Wallet für A-TownChain OS — Keys, Tokens, Contracts, DeFi.

## Features
- **Key Management** — Ed25519 Keys, Mnemonic, HD-Wallet (BIP44)
- **Multi-Account** — Mehrere Accounts in einem Wallet
- **Token Transfer** — ATC Token, Custom Tokens, NFTs
- **Contract Interaction** — Smart Contracts aufrufen
- **DeFi** — Staking, Swap, Liquidity
- **Hardware Wallet** — Ledger, Trezor Support
- **Multi-Sig** — Multi-Signature Wallets (GCL v2.0)

## Sicherheit
- Private Keys NIE im Klartext gespeichert (AES-256 verschlüsselt)
- Mnemonic-Backup mit BIP39
- Transaction-Signing offline (Air-Gapped Mode)
- Biometric Auth (Mobile)

## Address Format
```
ATC + 40 hex chars (20 bytes Ed25519 public key)
Example: ATCf9327118a7dfb30f72ba6aa82e1186078c42232884
Checksum: Base58 with version byte
```

## Verwandte Repos
- [atc-sdk](https://github.com/A-TownChain-Okosystems/atc-sdk) — SDK
- [atc-contracts](https://github.com/A-TownChain-Okosystems/atc-contracts) — Smart Contracts
- [atc-cli](https://github.com/A-TownChain-Okosystems/atc-cli) — CLI

[agent: aurora-base44-superagent-6a2756186106d6f0fbb105b5]
