# multi_chain_wallet

Pure Dart mnemonic-based wallet derivation for multiple chains.

## Supported chains

- `bitcoin` - legacy P2PKH (`1...`)
- `bitcoinSegwit` - native SegWit / bech32 (`bc1q...`)
- `dogecoin`
- `eth`
- `bnb`
- `tron`
- `xrpl` - native XRP Ledger (`r...`)
- `xrpEvm` - EVM-style XRP address (`0x...`)
- `solana`
- `sui` - Ed25519 + Blake2b address (`0x...`)

## Features

- Derive private key, public key, and address from a mnemonic
- Batch derivation across all supported chains
- Chain metadata lookup by chain id
- Pure Dart implementation with unit tests

## Usage

```dart
import 'package:multi_chain_wallet/wallet_derivation.dart';

Future<void> main() async {
  const mnemonic =
      'baby pretty venture start report sick shuffle axis tube laugh cement train';

  final ethWallet = await MnemonicWallet.derive(
    mnemonic: mnemonic,
    chain: SupportedChain.eth,
  );

  final xrplWallet = await MnemonicWallet.derive(
    mnemonic: mnemonic,
    chain: SupportedChain.xrpl,
  );

  final canonical = SupportedChainX.fromChainId(60);
  final allFor60 = SupportedChainX.allForChainId(60);

  print(ethWallet.address);
  print(xrplWallet.address);
  print(canonical);
  print(allFor60);
}
```

## Notes

- `chainId` in this package follows the BIP44 / SLIP-0044 coin type style used by derivation paths.
- Some chains share the same id. For example `eth`, `bnb`, and `xrpEvm` all map to `60`.
- `sui` uses path `m/44'/784'/0'/0'/0'` and address `0x + blake2b-256(0x00 || publicKey)`.
- `SupportedChainX.fromChainId` returns the canonical default chain for that id.
- `SupportedChainX.allForChainId` returns every supported chain that shares the same id.

## Publishing

Before publishing to pub.dev, make sure you also set:

- `homepage`
- `repository`
- `issue_tracker`
- a license file such as `LICENSE`

Then run:

```bash
dart pub publish --dry-run
dart pub publish
```
