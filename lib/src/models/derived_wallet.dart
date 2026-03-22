import '../chains/supported_chain.dart';

class DerivedWallet {
  const DerivedWallet({
    required this.chain,
    required this.path,
    required this.privateKeyHex,
    required this.publicKeyHex,
    required this.address,
  });

  final SupportedChain chain;
  final String path;
  final String privateKeyHex;
  final String publicKeyHex;
  final String address;
}
