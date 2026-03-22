import 'package:multi_chain_wallet/multi_chain_wallet.dart';
import 'package:test/test.dart';

void main() {
  const mnemonic =
      'baby pretty venture start report sick shuffle axis tube laugh cement train';

  group('SupportedChain', () {
    test('fromChainId returns the canonical chain for known ids', () {
      expect(SupportedChainX.fromChainId(0), SupportedChain.bitcoin);
      expect(SupportedChainX.fromChainId(3), SupportedChain.dogecoin);
      expect(SupportedChainX.fromChainId(60), SupportedChain.eth);
      expect(SupportedChainX.fromChainId(144), SupportedChain.xrpl);
      expect(SupportedChainX.fromChainId(195), SupportedChain.tron);
      expect(SupportedChainX.fromChainId(501), SupportedChain.solana);
      expect(SupportedChainX.fromChainId(999999), isNull);
    });

    test('allForChainId returns every chain that shares the same id', () {
      expect(
        SupportedChainX.allForChainId(60),
        [SupportedChain.eth, SupportedChain.bnb, SupportedChain.xrpEvm],
      );
    });
  });

  group('MnemonicWallet', () {
    test('mnemonicToSeed matches the BIP39 test vector', () {
      final seed = MnemonicWallet.mnemonicToSeed(mnemonic);
      expect(
        _toHex(seed),
        'f258daa11426161c50821b466a9aca1ca238c4e9543da28992983c71b25fda19'
        '3b777a026ae462aa85bbe291c78ae60e582544ed204266facd7a0c3510a8cc60',
      );
    });

    test('derives the expected Bitcoin wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.bitcoin,
      );

      expect(wallet.path, "m/44'/0'/0'/0/0");
      expect(wallet.privateKeyHex,
          'ce5f28f2627eb66319832902f92afc579e3b70ce61471e78a97cd02cad1e3105');
      expect(wallet.publicKeyHex,
          '02cd4439cd74a05dbd196a885ed026cea17e7fbd5837f576c15bd63c9752dae133');
      expect(wallet.address, '1MypTYG8jWfmK2tMDou9LcryMa4v5CxCoS');
    });

    test('derives the expected Bitcoin SegWit wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.bitcoinSegwit,
      );

      expect(wallet.path, "m/84'/0'/0'/0/0");
      expect(wallet.privateKeyHex,
          'cece2806280aa581b8c52f4ab3eaf813970d26985d9d873db75823d54b27e44a');
      expect(wallet.publicKeyHex,
          '025c3e9587dc7c83166d4530b55db7415031725e12fd5f2568a000b3c7993b0b95');
      expect(wallet.address, 'bc1qcleyua9gl9jlr0fvqpvxxtlstmu49u2wk0qqju');
    });

    test('derives the expected Dogecoin wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.dogecoin,
      );

      expect(wallet.path, "m/44'/3'/0'/0/0");
      expect(wallet.privateKeyHex,
          '6fe4fa20e15d0138618d2e5582b4da534a83c9f9011b556618acd36b4573fec2');
      expect(wallet.publicKeyHex,
          '03368506022d8f92b0c5e5f58804eb866ca14c8b4fbf4ac2e185ba1e283fe0ed5b');
      expect(wallet.address, 'DHWjyNW99KW61BzvcdLdvS6xFkCwqCP33a');
    });

    test('derives the expected ETH wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.eth,
      );

      expect(wallet.path, "m/44'/60'/0'/0/0");
      expect(wallet.privateKeyHex,
          '0ef855124e04de4f13051d4c70bbe6585d3e293ca8ec59139780ba245375f8f3');
      expect(
        wallet.publicKeyHex,
        '60205c6dc2a5e736d4f7ee6f6cd9b42f652724d3c661d3fd21f7b1ce0ea134b8'
        'f2aa6b4e78784a244bbaf88b66c100bacc01be29b06d1d88cbb8cde0e60042f9',
      );
      expect(wallet.address, '0xff87baeeb8a7af69ef5dccfb8fb6515e3775f1d7');
    });

    test('derives the expected BNB wallet using the EVM path', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.bnb,
      );

      expect(wallet.path, "m/44'/60'/0'/0/0");
      expect(wallet.address, '0xff87baeeb8a7af69ef5dccfb8fb6515e3775f1d7');
    });

    test('derives the expected TRON wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.tron,
      );

      expect(wallet.path, "m/44'/195'/0'/0/0");
      expect(wallet.privateKeyHex,
          '14682267714c578cd151e7588355be2570032fc3f136cdeeb6eb4fa80de95299');
      expect(wallet.address, 'T9yYWtyaXGEBvXTDj9d39L7SxDF6Z4qsNs');
    });

    test('derives the expected XRPL wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.xrpl,
      );

      expect(wallet.path, "m/44'/144'/0'/0/0");
      expect(wallet.privateKeyHex,
          'bec7f753980cbc5e874b8f83a49293044fa4dde79bd7c01dbcda2127749d53ef');
      expect(wallet.publicKeyHex,
          '03b342da8f9ee5ede1481a943381cac0ae06cf9e424dc2adb3d4fe5dc2f1daed18');
      expect(wallet.address, 'rhjbymHTBDcaHnnpjx4EnWHuWbH2wMeiMZ');
    });

    test('derives the expected XRP EVM wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.xrpEvm,
      );

      expect(wallet.path, "m/44'/60'/0'/0/0");
      expect(wallet.privateKeyHex,
          '0ef855124e04de4f13051d4c70bbe6585d3e293ca8ec59139780ba245375f8f3');
      expect(
        wallet.publicKeyHex,
        '60205c6dc2a5e736d4f7ee6f6cd9b42f652724d3c661d3fd21f7b1ce0ea134b8'
        'f2aa6b4e78784a244bbaf88b66c100bacc01be29b06d1d88cbb8cde0e60042f9',
      );
      expect(wallet.address, '0xff87baeeb8a7af69ef5dccfb8fb6515e3775f1d7');
    });

    test('derives the expected Solana wallet', () async {
      final wallet = await MnemonicWallet.derive(
        mnemonic: mnemonic,
        chain: SupportedChain.solana,
      );

      expect(wallet.path, "m/44'/501'/0'/0'");
      expect(wallet.privateKeyHex,
          '73398ed9ce607c437b79808d1348db609dc337a7c83ebc64ad2b5ec078f21e51');
      expect(
        wallet.publicKeyHex,
        'b4c4bfbc5c1b45b4b3d4737434c1cef141e5215812eacc916f8636858de91fe5',
      );
      expect(wallet.address, 'DAePhcFaiy3hRjm8uGojUrUCvuRyqjmyMfQF4aNXMkcC');
    });

    test('deriveAll returns all supported chains', () async {
      final wallets = await MnemonicWallet.deriveAll(mnemonic: mnemonic);

      expect(wallets.keys.toSet(), SupportedChain.values.toSet());
      expect(wallets[SupportedChain.bitcoin]!.address,
          '1MypTYG8jWfmK2tMDou9LcryMa4v5CxCoS');
      expect(wallets[SupportedChain.bitcoinSegwit]!.address,
          'bc1qcleyua9gl9jlr0fvqpvxxtlstmu49u2wk0qqju');
      expect(wallets[SupportedChain.dogecoin]!.address,
          'DHWjyNW99KW61BzvcdLdvS6xFkCwqCP33a');
      expect(wallets[SupportedChain.eth]!.address,
          '0xff87baeeb8a7af69ef5dccfb8fb6515e3775f1d7');
      expect(wallets[SupportedChain.tron]!.address,
          'T9yYWtyaXGEBvXTDj9d39L7SxDF6Z4qsNs');
      expect(wallets[SupportedChain.xrpl]!.address,
          'rhjbymHTBDcaHnnpjx4EnWHuWbH2wMeiMZ');
      expect(wallets[SupportedChain.xrpEvm]!.address,
          '0xff87baeeb8a7af69ef5dccfb8fb6515e3775f1d7');
      expect(wallets[SupportedChain.solana]!.address,
          'DAePhcFaiy3hRjm8uGojUrUCvuRyqjmyMfQF4aNXMkcC');
    });

    test('fromPrivateKey rebuilds the expected Bitcoin SegWit wallet',
        () async {
      final wallet = await MnemonicWallet.fromPrivateKey(
        privateKeyHex:
            'cece2806280aa581b8c52f4ab3eaf813970d26985d9d873db75823d54b27e44a',
        chain: SupportedChain.bitcoinSegwit,
      );

      expect(wallet.address, 'bc1qcleyua9gl9jlr0fvqpvxxtlstmu49u2wk0qqju');
      expect(wallet.publicKeyHex,
          '025c3e9587dc7c83166d4530b55db7415031725e12fd5f2568a000b3c7993b0b95');
    });

    test('fromPrivateKey rebuilds the expected XRPL wallet', () async {
      final wallet = await MnemonicWallet.fromPrivateKey(
        privateKeyHex:
            'bec7f753980cbc5e874b8f83a49293044fa4dde79bd7c01dbcda2127749d53ef',
        chain: SupportedChain.xrpl,
      );

      expect(wallet.address, 'rhjbymHTBDcaHnnpjx4EnWHuWbH2wMeiMZ');
      expect(wallet.publicKeyHex,
          '03b342da8f9ee5ede1481a943381cac0ae06cf9e424dc2adb3d4fe5dc2f1daed18');
    });

    test('addressFromPrivateKey returns the expected XRP EVM address',
        () async {
      final address = await MnemonicWallet.addressFromPrivateKey(
        privateKeyHex:
            '0x0bdf81a6767054c420121063394d38979349295fefb3c12cbd94db3c01d1ff52',
        chain: SupportedChain.xrpEvm,
      );

      expect(address, '0x241fd68f26db9aee857717d6cca805db898ca051');
    });

    test('addressFromPrivateKey returns the expected TRON address', () async {
      final address = await MnemonicWallet.addressFromPrivateKey(
        privateKeyHex:
            '0x0bdf81a6767054c420121063394d38979349295fefb3c12cbd94db3c01d1ff52',
        chain: SupportedChain.tron,
      );

      expect(address, 'TDGDU7hksRQDTUfndaJQoGhbvWeYWaBqHz');
    });

    test('rejects an empty mnemonic', () {
      expect(
        () => MnemonicWallet.mnemonicToSeed('   '),
        throwsArgumentError,
      );
    });

    test('rejects invalid private key length', () {
      expect(
        () => MnemonicWallet.fromPrivateKey(
          privateKeyHex: '1234',
          chain: SupportedChain.eth,
        ),
        throwsArgumentError,
      );
    });
  });
}

String _toHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
