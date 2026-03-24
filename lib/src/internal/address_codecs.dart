import 'dart:typed_data';

import 'package:pointycastle/digests/keccak.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/export.dart' show SHA256Digest;

import 'bytes.dart';

const String bitcoinBase58Alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const String xrpBase58Alphabet =
    'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdefghijkLmnoqtuvAxyz';
const String bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

String ethereumAddress(Uint8List uncompressedPublicKey) {
  final hash = KeccakDigest(256).process(uncompressedPublicKey);
  final rawAddress = Uint8List.sublistView(hash, hash.length - 20);
  return '0x${bytesToHex(rawAddress)}';
}

String tronAddress(Uint8List uncompressedPublicKey) {
  final hash = KeccakDigest(256).process(uncompressedPublicKey);
  final payload = Uint8List.fromList([0x41, ...hash.sublist(hash.length - 20)]);
  final checksum = SHA256Digest()
      .process(SHA256Digest().process(payload))
      .sublist(0, 4);
  return base58Encode([...payload, ...checksum]);
}

Uint8List hash160(List<int> bytes) {
  final sha = SHA256Digest().process(Uint8List.fromList(bytes));
  return RIPEMD160Digest().process(sha);
}

String base58CheckEncode(
  List<int> payload, {
  String alphabet = bitcoinBase58Alphabet,
}) {
  final checksum = SHA256Digest()
      .process(SHA256Digest().process(Uint8List.fromList(payload)))
      .sublist(0, 4);
  return base58EncodeWithAlphabet([...payload, ...checksum], alphabet);
}

String base58Encode(List<int> bytes) {
  return base58EncodeWithAlphabet(bytes, bitcoinBase58Alphabet);
}

String base58EncodeWithAlphabet(List<int> bytes, String alphabet) {
  if (bytes.isEmpty) {
    return '';
  }

  final base = BigInt.from(alphabet.length);
  var value = decodeBigInt(bytes);
  final output = StringBuffer();

  while (value > BigInt.zero) {
    final div = value ~/ base;
    final mod = (value - div * base).toInt();
    output.write(alphabet[mod]);
    value = div;
  }

  for (final byte in bytes) {
    if (byte != 0) {
      break;
    }
    output.write(alphabet[0]);
  }

  return output.toString().split('').reversed.join();
}

String encodeSegwitAddress({
  required String hrp,
  required int witnessVersion,
  required Uint8List witnessProgram,
}) {
  final data = <int>[
    witnessVersion,
    ...convertBits(witnessProgram, from: 8, to: 5, pad: true),
  ];
  final checksum = bech32CreateChecksum(hrp, data);
  final encoded = [...data, ...checksum].map((v) => bech32Charset[v]).join();
  return '${hrp}1$encoded';
}

List<int> convertBits(
  List<int> data, {
  required int from,
  required int to,
  required bool pad,
}) {
  var acc = 0;
  var bits = 0;
  final result = <int>[];
  final maxv = (1 << to) - 1;

  for (final value in data) {
    if (value < 0 || (value >> from) != 0) {
      throw ArgumentError('Invalid value for bit conversion.');
    }
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      result.add((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.add((acc << (to - bits)) & maxv);
    }
  } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
    throw ArgumentError('Invalid padding in bit conversion.');
  }

  return result;
}

List<int> bech32CreateChecksum(String hrp, List<int> data) {
  final values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  final polymod = bech32Polymod(values) ^ 1;
  return List<int>.generate(
    6,
    (index) => (polymod >> (5 * (5 - index))) & 31,
    growable: false,
  );
}

List<int> bech32HrpExpand(String hrp) {
  final codes = hrp.codeUnits;
  return [...codes.map((code) => code >> 5), 0, ...codes.map((code) => code & 31)];
}

int bech32Polymod(List<int> values) {
  const generators = <int>[
    0x3b6a57b2,
    0x26508e6d,
    0x1ea119fa,
    0x3d4233dd,
    0x2a1462b3,
  ];

  var chk = 1;
  for (final value in values) {
    final top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (var i = 0; i < generators.length; i++) {
      if (((top >> i) & 1) != 0) {
        chk ^= generators[i];
      }
    }
  }
  return chk;
}

Uint8List base58Decode(String input, {String alphabet = bitcoinBase58Alphabet}) {
  if (input.isEmpty) {
    return Uint8List(0);
  }

  final base = BigInt.from(alphabet.length);
  var value = BigInt.zero;
  for (final char in input.codeUnits) {
    final index = alphabet.indexOf(String.fromCharCode(char));
    if (index == -1) {
      throw ArgumentError('Invalid character in base58 string: $char');
    }
    value = value * base + BigInt.from(index);
  }

  final bytes = <int>[];
  while (value > BigInt.zero) {
    bytes.add((value % BigInt.from(256)).toInt());
    value ~/= BigInt.from(256);
  }

  // Add leading zeros
  for (final char in input.codeUnits) {
    if (String.fromCharCode(char) != alphabet[0]) {
      break;
    }
    bytes.add(0);
  }

  return Uint8List.fromList(bytes.reversed.toList());
}
