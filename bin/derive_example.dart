import 'package:multi_chain_wallet/wallet_derivation.dart';

Future<void> main() async {
  const mnemonic =
      'baby pretty venture start report sick shuffle axis tube laugh cement train';

  for (final chain in SupportedChain.values) {
    final wallet = await MnemonicWallet.derive(
      mnemonic: mnemonic,
      chain: chain,
    );
    print('${chain.name}:');
    print('  path: ${wallet.path}');
    print('  private: ${wallet.privateKeyHex}');
    print('  public: ${wallet.publicKeyHex}');
    print('  address: ${wallet.address}');
  }
}
