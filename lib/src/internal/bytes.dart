import 'dart:convert';
import 'dart:typed_data';

String bytesToHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

Uint8List uint32BigEndian(int value) {
  final data = ByteData(4)..setUint32(0, value, Endian.big);
  return data.buffer.asUint8List();
}

BigInt decodeBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

Uint8List bigIntToBytes(BigInt value, int length) {
  final result = Uint8List(length);
  var temp = value;
  for (var i = length - 1; i >= 0; i--) {
    result[i] = (temp & BigInt.from(0xff)).toInt();
    temp >>= 8;
  }
  return result;
}

Uint8List utf8Bytes(String value) => Uint8List.fromList(utf8.encode(value));

Uint8List privateKeyFromHex(String privateKeyHex) {
  final normalized = privateKeyHex.startsWith('0x')
      ? privateKeyHex.substring(2)
      : privateKeyHex;

  if (normalized.length != 64) {
    throw ArgumentError.value(
      privateKeyHex,
      'privateKeyHex',
      'Private key must be exactly 32 bytes in hex format.',
    );
  }

  final bytes = List<int>.generate(
    normalized.length ~/ 2,
    (index) => int.parse(
      normalized.substring(index * 2, index * 2 + 2),
      radix: 16,
    ),
    growable: false,
  );
  return Uint8List.fromList(bytes);
}
