# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pure Dart package (no Flutter dependency) for BIP39 mnemonic-based wallet derivation across multiple blockchain chains. Published to pub.dev as `multi_chain_wallet`.

## Commands

```bash
# Run all tests
dart test

# Run a single test by name
dart test --name "test name substring"

# Run the example
dart run bin/derive_example.dart

# Analyze for lint issues
dart analyze

# Dry-run publish check
dart pub publish --dry-run
```

## Architecture

**Entry point**: `lib/multi_chain_wallet.dart` → re-exports `src/src_exports.dart`

**Core class**: `MnemonicWallet` in `lib/src/mnemonic_wallet.dart` — static-only utility class (private constructor). All public API methods live here: `derive()`, `deriveAll()`, `fromPrivateKey()`, `sign()`, `signPersonalMessage()`.

**Key derivation** dispatches to two families:
- `Bip32Secp256k1` — BIP32 for secp256k1 chains (Bitcoin, Dogecoin, ETH, BNB, TRON, XRPL, XRP EVM)
- `Slip10Ed25519` — SLIP-0010 for Ed25519 chains (Solana, Sui)

**Internal modules** (`lib/src/internal/`):
- `derivation_nodes.dart` — BIP32/SLIP-0010 key derivation implementations
- `address_codecs.dart` — address encoding (base58check, bech32, Keccak, Blake2b)
- `bytes.dart` — byte/hex conversion utilities

**Chain definitions**: `SupportedChain` enum in `lib/src/chains/supported_chain.dart` with `SupportedChainX` extension for metadata lookup (`chainId`, `defaultPath`, `isEvm`, `fromChainId`, `allForChainId`).

**Data model**: `DerivedWallet` in `lib/src/models/derived_wallet.dart` — immutable data class with `chain`, `path`, `privateKeyHex`, `publicKeyHex`, `address`.

## Adding a New Chain

1. Add enum value to `SupportedChain` and its metadata entry in `_chainInfo` list in `supported_chain.dart`
2. Add a derivation method in `mnemonic_wallet.dart` (use existing `_deriveEvm` for EVM-compatible chains)
3. Add a `case` in `derive()` switch and `fromPrivateKey()` switch
4. Add address encoding in `address_codecs.dart` if needed
5. Add tests in `test/mnemonic_wallet_test.dart` with known expected values

## Key Design Notes

- ETH, BNB, and XRP EVM share BIP44 coin type 60 and the same key material — they differ only in address encoding.
- `DerivedWallet.privateKeyHex` stores base58 for Solana, not hex (despite the field name).
- `sign()` and `signPersonalMessage()` currently only support Solana; other chains throw `UnsupportedError`.
- `validateMnemonic()` only checks for non-empty input; no BIP39 wordlist/checksum validation yet.
