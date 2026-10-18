"""Base58 and Base58Check encoding in pure Python (zero dependencies).

Base58Check is the encoding behind Bitcoin legacy addresses (P2PKH/P2SH) and
WIF private keys: a version byte + payload, checksummed with the first 4
bytes of double-SHA256, then encoded in the 58-character Bitcoin alphabet.

>>> from base58check import b58encode, b58decode
>>> b58encode(b"\\x00")
'1'
>>> b58encode(b"\\x00\\x00")
'11'
>>> b58decode("1")
b'\\x00'

The genesis address round-trips and decodes to version 0x00 + 20 bytes:

>>> from base58check import b58check_decode
>>> version, payload = b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
>>> version, len(payload)
(0, 20)
>>> from base58check import b58check_encode
>>> b58check_encode(version, payload)
'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'

A WIF key for private key 0x01 (canonical wiki example) decodes to
version 0x80 with the 32-byte big-endian private key ending in 0x01:

>>> version, payload = b58check_decode("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
>>> version
128
>>> payload == (b"\\x00" * 31) + b"\\x01"
True
>>> b58check_encode(version, payload)
'5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'

Bad characters and tampered checksums are rejected:

>>> b58decode("0OIl")  # doctest: +IGNORE_EXCEPTION_DETAIL
Traceback (most recent call last):
...
ValueError: invalid Base58 character '0' at position 0
>>> b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
Traceback (most recent call last):
...
ValueError: Base58Check checksum mismatch
>>> b58check_encode(256, b"")
Traceback (most recent call last):
...
ValueError: version must be a single byte
"""

import argparse
import hashlib

__all__ = [
    "ALPHABET",
    "b58encode",
    "b58decode",
    "b58check_encode",
    "b58check_decode",
    "p2pkh_address",
    "p2sh_address",
    "wif_encode",
    "wif_decode",
    "main",
]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}

# Common version prefixes (Bitcoin mainnet)
VERSION_P2PKH = 0x00   # addresses starting with '1'
VERSION_P2SH = 0x05    # addresses starting with '3'
VERSION_WIF = 0x80     # WIF private keys starting with '5' (uncompressed)
VERSION_WIF_COMPRESSED = 0x80  # + 0x01 suffix on the payload


def _sha256d(data: bytes) -> bytes:
    """Double SHA-256, Bitcoin's checksum primitive."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58encode(data: bytes) -> str:
    """Encode raw bytes to a Base58 string (preserves leading zero bytes as '1').

    >>> b58encode(b"")
    ''
    >>> b58encode(b"\\x00\\x00\\x01")
    '112'
    >>> b58encode(b"hello")  # == binascii-independent reference
    'Cn8eVZg'
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    num = int.from_bytes(data, "big")
    digits = []
    while num > 0:
        num, rem = divmod(num, 58)
        digits.append(ALPHABET[rem])
    return "1" * leading_zeros + "".join(reversed(digits))


def b58decode(text: str) -> bytes:
    """Decode a Base58 string to raw bytes (leading '1's become zero bytes).

    >>> b58decode("")
    b''
    >>> b58decode("112")
    b'\\x00\\x00\\x01'
    >>> b58decode(b58encode(b"round trip \\x00\\xff"))
    b'round trip \\x00\\xff'
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    leading_ones = 0
    for ch in text:
        if ch == "1":
            leading_ones += 1
        else:
            break
    num = 0
    for pos, ch in enumerate(text):
        digit = _ALPHABET_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"invalid Base58 character {ch!r} at position {pos}")
        num = num * 58 + digit
    payload = b"" if num == 0 else num.to_bytes((num.bit_length() + 7) // 8, "big")
    return b"\x00" * leading_ones + payload


def b58check_encode(version: int, payload: bytes) -> str:
    """Base58Check: version byte + payload + 4-byte double-SHA256 checksum.

    >>> b58check_encode(VERSION_P2PKH, bytes(20))  # doctest: +ELLIPSIS
    '1111111111111111111114oLvT2'
    """
    if not isinstance(version, int) or not 0 <= version <= 255:
        raise ValueError("version must be a single byte")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    data = bytes([version]) + bytes(payload)
    checksum = _sha256d(data)[:4]
    return b58encode(data + checksum)


def b58check_decode(text: str) -> tuple:
    """Inverse of b58check_encode: returns (version, payload), checks checksum."""
    raw = b58decode(text)
    if len(raw) < 5:
        raise ValueError("Base58Check payload too short")
    version, payload, checksum = raw[0], raw[1:-4], raw[-4:]
    if _sha256d(raw[:-4])[:4] != checksum:
        raise ValueError("Base58Check checksum mismatch")
    return version, payload


def p2pkh_address(pubkey_hash: bytes) -> str:
    """Encode a 20-byte HASH160 as a legacy '1...' P2PKH address."""
    if len(pubkey_hash) != 20:
        raise ValueError("P2PKH payload must be 20 bytes")
    return b58check_encode(VERSION_P2PKH, pubkey_hash)


def p2sh_address(script_hash: bytes) -> str:
    """Encode a 20-byte HASH160 as a legacy '3...' P2SH address."""
    if len(script_hash) != 20:
        raise ValueError("P2SH payload must be 20 bytes")
    return b58check_encode(VERSION_P2SH, script_hash)


def wif_encode(privkey: bytes, compressed: bool = False) -> str:
    """Encode a 32-byte private key as Wallet Import Format (version 0x80)."""
    if len(privkey) != 32:
        raise ValueError("private key must be 32 bytes")
    payload = bytes(privkey) + (b"\x01" if compressed else b"")
    return b58check_encode(VERSION_WIF, payload)


def wif_decode(text: str) -> tuple:
    """Decode WIF: returns (private_key_bytes, compressed)."""
    version, payload = b58check_decode(text)
    if version != VERSION_WIF:
        raise ValueError(f"not a WIF key (version {version})")
    if len(payload) == 33 and payload[-1:] == b"\x01":
        return payload[:-1], True
    if len(payload) == 32:
        return payload, False
    raise ValueError("malformed WIF payload")


def demo() -> None:
    print("Base58:", b58encode(b"hello world"))
    print("Genesis P2PKH:", b58check_encode(0x00, b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")[1]))
    print("WIF of 0x01:", wif_encode((b"\x00" * 31) + b"\x01"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Base58 / Base58Check encoder")
    parser.add_argument("--demo", action="store_true", help="print a short demo")
    parser.add_argument("--test", action="store_true", help="run the doctests")
    args = parser.parse_args(argv)
    if args.test:
        import doctest

        results = doctest.testmod(verbose=False)
        print(f"{results.attempted - results.failed} passed, {results.failed} failed")
        return 1 if results.failed else 0
    if args.demo:
        demo()
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
