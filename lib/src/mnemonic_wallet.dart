import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/export.dart'
    show
        Blake2bDigest,
        HMac,
        PBKDF2KeyDerivator,
        Pbkdf2Parameters,
        SHA512Digest;

import 'chains/supported_chain.dart';
import 'internal/address_codecs.dart';
import 'internal/bytes.dart';
import 'internal/derivation_nodes.dart';
import 'models/derived_wallet.dart';

/// Public API for deterministic wallet derivation from a mnemonic.
///
/// The class intentionally keeps only orchestration logic.
/// Low-level derivation and encoding details live in dedicated internal modules,
/// which makes it easier to add new chains without turning this file into a
/// maintenance bottleneck.
class MnemonicWallet {
  MnemonicWallet._();

  static const String defaultPassphrase = '';

  /// Derives a single wallet for the requested chain.
  static Future<DerivedWallet> derive({
    required String mnemonic,
    required SupportedChain chain,
    String passphrase = defaultPassphrase,
  }) async {
    validateMnemonic(mnemonic);
    final seed = mnemonicToSeed(mnemonic, passphrase: passphrase);

    switch (chain) {
      case SupportedChain.bitcoin:
        return _deriveBitcoinLegacy(seed);
      case SupportedChain.bitcoinSegwit:
        return _deriveBitcoinSegwit(seed);
      case SupportedChain.dogecoin:
        return _deriveDogecoin(seed);
      case SupportedChain.eth:
        return _deriveEvm(seed, SupportedChain.eth);
      case SupportedChain.bnb:
        return _deriveEvm(seed, SupportedChain.bnb);
      case SupportedChain.tron:
        return _deriveTron(seed);
      case SupportedChain.xrpl:
        return _deriveXrpl(seed);
      case SupportedChain.xrpEvm:
        return _deriveEvm(seed, SupportedChain.xrpEvm);
      case SupportedChain.solana:
        return _deriveSolana(seed);
      case SupportedChain.sui:
        return _deriveSui(seed);
    }
  }

  /// Derives all currently supported chains with the same mnemonic.
  static Future<Map<SupportedChain, DerivedWallet>> deriveAll({
    required String mnemonic,
    String passphrase = defaultPassphrase,
  }) async {
    final result = <SupportedChain, DerivedWallet>{};
    for (final chain in SupportedChain.values) {
      result[chain] = await derive(
        mnemonic: mnemonic,
        chain: chain,
        passphrase: passphrase,
      );
    }
    return result;
  }

  /// Builds a wallet model directly from a raw private key.
  ///
  /// This is useful when the caller already stores the private key and only
  /// needs the matching public key and address in the format of a target chain.
  static Future<DerivedWallet> fromPrivateKey({
    required String privateKeyHex,
    required SupportedChain chain,
  }) async {
    final privateKey = privateKeyFromHex(privateKeyHex);

    switch (chain) {
      case SupportedChain.bitcoin:
        return _fromBase58UtxoPrivateKey(
          privateKey: privateKey,
          chain: chain,
          version: 0x00,
        );
      case SupportedChain.bitcoinSegwit:
        return _fromBitcoinSegwitPrivateKey(privateKey);
      case SupportedChain.dogecoin:
        return _fromBase58UtxoPrivateKey(
          privateKey: privateKey,
          chain: chain,
          version: 0x1e,
        );
      case SupportedChain.eth:
        return _fromEvmPrivateKey(privateKey, SupportedChain.eth);
      case SupportedChain.bnb:
        return _fromEvmPrivateKey(privateKey, SupportedChain.bnb);
      case SupportedChain.tron:
        return _fromTronPrivateKey(privateKey);
      case SupportedChain.xrpl:
        return _fromXrplPrivateKey(privateKey);
      case SupportedChain.xrpEvm:
        return _fromEvmPrivateKey(privateKey, SupportedChain.xrpEvm);
      case SupportedChain.solana:
        final privateKey = base58Decode(privateKeyHex);
        return _fromSolanaPrivateKey(privateKey);
      case SupportedChain.sui:
        return _fromSuiPrivateKey(privateKey);
    }
  }

  /// Convenience API when the caller only needs the address text.
  static Future<String> addressFromPrivateKey({
    required String privateKeyHex,
    required SupportedChain chain,
  }) async {
    final wallet = await fromPrivateKey(
      privateKeyHex: privateKeyHex,
      chain: chain,
    );
    return wallet.address;
  }

  /// Converts a BIP39 mnemonic into the 64-byte seed used by the chain
  /// derivation helpers below.
  static Uint8List mnemonicToSeed(
    String mnemonic, {
    String passphrase = defaultPassphrase,
  }) {
    validateMnemonic(mnemonic);
    final normalizedMnemonic = mnemonic.trim().split(RegExp(r'\s+')).join(' ');
    final salt = 'mnemonic$passphrase';
    final derivator = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))
      ..init(Pbkdf2Parameters(utf8Bytes(salt), 2048, 64));

    return derivator.process(utf8Bytes(normalizedMnemonic));
  }

  /// Lightweight validation for empty input.
  ///
  /// Full BIP39 checksum/wordlist validation can be added later without
  /// changing the public API.
  static void validateMnemonic(String mnemonic) {
    final words = mnemonic
        .trim()
        .split(RegExp(r'\s+'))
        .where((word) => word.isNotEmpty)
        .toList(growable: false);
    if (words.isEmpty) {
      throw ArgumentError.value(
        mnemonic,
        'mnemonic',
        'Mnemonic cannot be empty.',
      );
    }
  }

  static DerivedWallet _deriveBitcoinLegacy(Uint8List seed) {
    return _deriveBase58Utxo(
      seed: seed,
      chain: SupportedChain.bitcoin,
      version: 0x00,
    );
  }

  static DerivedWallet _deriveBitcoinSegwit(Uint8List seed) {
    final chain = SupportedChain.bitcoinSegwit;
    final node = Bip32Secp256k1.fromSeed(seed).derivePath(chain.defaultPath);
    final publicKey = Bip32Secp256k1.compressedPublicKey(node.privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(node.privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: encodeSegwitAddress(
        hrp: 'bc',
        witnessVersion: 0,
        witnessProgram: hash160(publicKey),
      ),
    );
  }

  static DerivedWallet _deriveDogecoin(Uint8List seed) {
    return _deriveBase58Utxo(
      seed: seed,
      chain: SupportedChain.dogecoin,
      version: 0x1e,
    );
  }

  static DerivedWallet _deriveBase58Utxo({
    required Uint8List seed,
    required SupportedChain chain,
    required int version,
  }) {
    final node = Bip32Secp256k1.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromBase58UtxoPrivateKey(
      privateKey: node.privateKey,
      chain: chain,
      version: version,
    );
  }

  static DerivedWallet _fromBase58UtxoPrivateKey({
    required Uint8List privateKey,
    required SupportedChain chain,
    required int version,
  }) {
    final publicKey = Bip32Secp256k1.compressedPublicKey(privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: base58CheckEncode([version, ...hash160(publicKey)]),
    );
  }

  static DerivedWallet _deriveEvm(Uint8List seed, SupportedChain chain) {
    final node = Bip32Secp256k1.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromEvmPrivateKey(node.privateKey, chain);
  }

  static DerivedWallet _fromEvmPrivateKey(
    Uint8List privateKey,
    SupportedChain chain,
  ) {
    final publicKey = _secp256k1UncompressedPublicKey(privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: ethereumAddress(publicKey),
    );
  }

  static DerivedWallet _deriveTron(Uint8List seed) {
    final chain = SupportedChain.tron;
    final node = Bip32Secp256k1.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromTronPrivateKey(node.privateKey);
  }

  static DerivedWallet _fromTronPrivateKey(Uint8List privateKey) {
    final chain = SupportedChain.tron;
    final publicKey = _secp256k1UncompressedPublicKey(privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: tronAddress(publicKey),
    );
  }

  static DerivedWallet _deriveXrpl(Uint8List seed) {
    final chain = SupportedChain.xrpl;
    final node = Bip32Secp256k1.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromXrplPrivateKey(node.privateKey);
  }

  static DerivedWallet _fromXrplPrivateKey(Uint8List privateKey) {
    final chain = SupportedChain.xrpl;
    final publicKey = Bip32Secp256k1.compressedPublicKey(privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: base58CheckEncode(
        [0x00, ...hash160(publicKey)],
        alphabet: xrpBase58Alphabet,
      ),
    );
  }

  static Future<DerivedWallet> _deriveSolana(Uint8List seed) async {
    final chain = SupportedChain.solana;
    final node = Slip10Ed25519.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromSolanaPrivateKey(node.privateKey);
  }

  static Future<DerivedWallet> _fromSolanaPrivateKey(
      Uint8List privateKey) async {
    final chain = SupportedChain.solana;
    final algorithm = Ed25519();
    // If 64 bytes, take first 32 as seed; otherwise use as seed
    final seed =
        privateKey.length == 64 ? privateKey.sublist(0, 32) : privateKey;
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    final publicKey = (await keyPair.extractPublicKey()).bytes;

    // Solana private key format: 64 bytes (32 private + 32 public), base58 encoded
    final fullPrivateKey = Uint8List.fromList([...seed, ...publicKey]);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: base58Encode(fullPrivateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: base58Encode(publicKey),
    );
  }

  static Future<DerivedWallet> _deriveSui(Uint8List seed) async {
    final chain = SupportedChain.sui;
    final node = Slip10Ed25519.fromSeed(seed).derivePath(chain.defaultPath);
    return _fromSuiPrivateKey(node.privateKey);
  }

  static Future<DerivedWallet> _fromSuiPrivateKey(Uint8List privateKey) async {
    final chain = SupportedChain.sui;
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPairFromSeed(privateKey);
    final publicKey = (await keyPair.extractPublicKey()).bytes;
    final address = _suiAddress(publicKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: address,
    );
  }

  static Future<DerivedWallet> _fromBitcoinSegwitPrivateKey(
    Uint8List privateKey,
  ) async {
    final chain = SupportedChain.bitcoinSegwit;
    final publicKey = Bip32Secp256k1.compressedPublicKey(privateKey);

    return DerivedWallet(
      chain: chain,
      path: chain.defaultPath,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey),
      address: encodeSegwitAddress(
        hrp: 'bc',
        witnessVersion: 0,
        witnessProgram: hash160(publicKey),
      ),
    );
  }

  static Uint8List _secp256k1UncompressedPublicKey(Uint8List privateKey) {
    final curve = ECCurve_secp256k1();
    final point = curve.G * decodeBigInt(privateKey);
    if (point == null) {
      throw StateError('Failed to derive public key.');
    }

    final x = bigIntToBytes(point.x!.toBigInteger()!, 32);
    final y = bigIntToBytes(point.y!.toBigInteger()!, 32);
    return Uint8List.fromList([...x, ...y]);
  }

  static String _suiAddress(List<int> publicKey) {
    // Sui address = 0x + blake2b-256(signature_scheme_flag || public_key)
    const ed25519Flag = 0x00;
    final digest = Blake2bDigest(digestSize: 32);
    final hash =
        digest.process(Uint8List.fromList([ed25519Flag, ...publicKey]));
    return '0x${bytesToHex(hash)}';
  }
}
