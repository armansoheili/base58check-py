# base58check-py

Base58 and Base58Check encoding in pure Python — zero dependencies.

Base58Check is the encoding behind Bitcoin legacy addresses (`1…` P2PKH,
`3…` P2SH) and WIF private keys: a one-byte version prefix plus payload,
checksummed with the first 4 bytes of double-SHA256, then encoded in the
58-character Bitcoin alphabet (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
which skips the easily-confused `0`, `O`, `I` and `l`).

## Features

- `b58encode` / `b58decode` — raw Base58, with leading zero bytes preserved as `1`s
- `b58check_encode` / `b58check_decode` — version + payload + 4-byte checksum,
  with checksum verification on decode
- Address helpers: `p2pkh_address`, `p2sh_address`
- Wallet Import Format: `wif_encode` / `wif_decode` (compressed and uncompressed)
- Clear `ValueError`s on invalid characters, bad checksums and malformed payloads
- 23 doctests covering the module, including the genesis block address
  (`1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`) and the canonical WIF example for
  private key `0x01`

## Quick start

```python
from base58check import b58check_encode, b58check_decode, wif_encode

# encode a P2PKH address from a 20-byte HASH160
addr = b58check_encode(0x00, bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"))
print(addr)  # 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# decode and verify the checksum
version, payload = b58check_decode(addr)

# Wallet Import Format for a private key
wif = wif_encode(bytes(31) + b"\x01")  # '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
```

## CLI

```sh
python3 base58check.py --demo   # short demonstration
python3 base58check.py --test   # run the doctests
```

## How Base58Check works

1. Take `version_byte || payload`
2. Compute `checksum = SHA256(SHA256(version_byte || payload))[:4]`
3. Base58-encode `version_byte || payload || checksum`

Each leading zero byte becomes a leading `1` — that is why all-zero
payloads decode to strings of `1`s.
