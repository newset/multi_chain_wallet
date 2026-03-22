import 'dart:typed_data';

import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/export.dart' show HMac, KeyParameter, SHA512Digest;

import 'bytes.dart';

const int hardenedOffset = 0x80000000;

class Bip32Node {
  const Bip32Node({
    required this.privateKey,
    required this.chainCode,
    required this.depth,
    required this.childNumber,
  });

  final Uint8List privateKey;
  final Uint8List chainCode;
  final int depth;
  final int childNumber;
}

class Bip32Secp256k1 extends Bip32Node {
  Bip32Secp256k1({
    required super.privateKey,
    required super.chainCode,
    required super.depth,
    required super.childNumber,
  });

  factory Bip32Secp256k1.fromSeed(Uint8List seed) {
    final mac = HMac(SHA512Digest(), 128)..init(_keyParameter('Bitcoin seed'));
    final digest = mac.process(seed);
    return Bip32Secp256k1(
      privateKey: Uint8List.fromList(digest.sublist(0, 32)),
      chainCode: Uint8List.fromList(digest.sublist(32)),
      depth: 0,
      childNumber: 0,
    );
  }

  Bip32Secp256k1 derivePath(String path) {
    var current = this;
    for (final index in parsePath(path, requireHardened: false)) {
      current = current.derive(index);
    }
    return current;
  }

  Bip32Secp256k1 derive(int index) {
    final hardened = index >= hardenedOffset;
    final data = Uint8List.fromList([
      if (hardened) 0x00 else ...compressedPublicKey(privateKey),
      ...(hardened ? privateKey : <int>[]),
      ...uint32BigEndian(index),
    ]);

    final mac = HMac(SHA512Digest(), 128)..init(_keyParameter(chainCode));
    final digest = mac.process(data);
    final il = digest.sublist(0, 32);
    final ir = digest.sublist(32);

    final curve = ECCurve_secp256k1();
    final child = (decodeBigInt(il) + decodeBigInt(privateKey)) % curve.n;
    if (child == BigInt.zero) {
      throw StateError('Derived an invalid secp256k1 private key.');
    }

    return Bip32Secp256k1(
      privateKey: bigIntToBytes(child, 32),
      chainCode: Uint8List.fromList(ir),
      depth: depth + 1,
      childNumber: index,
    );
  }

  static Uint8List compressedPublicKey(Uint8List privateKey) {
    final curve = ECCurve_secp256k1();
    final point = curve.G * decodeBigInt(privateKey);
    if (point == null) {
      throw StateError('Failed to derive compressed public key.');
    }

    final x = bigIntToBytes(point.x!.toBigInteger()!, 32);
    final prefix = point.y!.toBigInteger()!.isEven ? 0x02 : 0x03;
    return Uint8List.fromList([prefix, ...x]);
  }
}

class Slip10Ed25519 extends Bip32Node {
  Slip10Ed25519({
    required super.privateKey,
    required super.chainCode,
    required super.depth,
    required super.childNumber,
  });

  factory Slip10Ed25519.fromSeed(Uint8List seed) {
    final mac = HMac(SHA512Digest(), 128)..init(_keyParameter('ed25519 seed'));
    final digest = mac.process(seed);
    return Slip10Ed25519(
      privateKey: Uint8List.fromList(digest.sublist(0, 32)),
      chainCode: Uint8List.fromList(digest.sublist(32)),
      depth: 0,
      childNumber: 0,
    );
  }

  Slip10Ed25519 derivePath(String path) {
    var current = this;
    for (final index in parsePath(path, requireHardened: true)) {
      current = current.derive(index);
    }
    return current;
  }

  Slip10Ed25519 derive(int index) {
    if (index < hardenedOffset) {
      throw ArgumentError('ed25519 only supports hardened derivation.');
    }

    final data = Uint8List.fromList([
      0x00,
      ...privateKey,
      ...uint32BigEndian(index),
    ]);

    final mac = HMac(SHA512Digest(), 128)..init(_keyParameter(chainCode));
    final digest = mac.process(data);

    return Slip10Ed25519(
      privateKey: Uint8List.fromList(digest.sublist(0, 32)),
      chainCode: Uint8List.fromList(digest.sublist(32)),
      depth: depth + 1,
      childNumber: index,
    );
  }
}

List<int> parsePath(String path, {required bool requireHardened}) {
  if (!path.startsWith('m')) {
    throw ArgumentError.value(
      path,
      'path',
      'Derivation path must start with "m".',
    );
  }

  if (path == 'm') {
    return const [];
  }

  return path
      .split('/')
      .skip(1)
      .map((segment) {
        final hardened = segment.endsWith("'");
        final raw = hardened ? segment.substring(0, segment.length - 1) : segment;
        final index = int.parse(raw);
        if (requireHardened && !hardened) {
          throw ArgumentError.value(
            path,
            'path',
            'This chain requires hardened-only path segments.',
          );
        }
        return hardened ? index + hardenedOffset : index;
      })
      .toList(growable: false);
}

KeyParameter _keyParameter(Object key) {
  return KeyParameter(
    key is String ? utf8Bytes(key) : key as Uint8List,
  );
}
