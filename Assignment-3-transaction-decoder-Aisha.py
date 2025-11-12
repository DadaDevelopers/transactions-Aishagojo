from __future__ import annotations
import struct, json, hashlib
from typing import List, Dict, Any


def decode_tx(hex_tx: str) -> Dict[str, Any]:
    data = bytearray.fromhex(hex_tx)
    pos = 0

    def read_bytes(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise ValueError('unexpected end of data')
        b = bytes(data[pos:pos+n])
        pos += n
        return b

    def read_uint32() -> int:
        return struct.unpack('<I', read_bytes(4))[0]

    def read_uint64() -> int:
        return struct.unpack('<Q', read_bytes(8))[0]

    def read_varint() -> int:
        nonlocal pos
        b = read_bytes(1)[0]
        if b < 0xfd:
            return b
        if b == 0xfd:
            return struct.unpack('<H', read_bytes(2))[0]
        if b == 0xfe:
            return struct.unpack('<I', read_bytes(4))[0]
        return struct.unpack('<Q', read_bytes(8))[0]

    def read_varbytes() -> bytes:
        l = read_varint()
        return read_bytes(l)

    start_pos = pos
    version = read_uint32()

  
    is_segwit = False
    if pos < len(data) and data[pos] == 0x00 and data[pos+1] == 0x01:
    
        _ = read_bytes(1)
        _ = read_bytes(1)
        is_segwit = True

    vin = []
    vin_count = read_varint()
    for i in range(vin_count):
        prev_txid = read_bytes(32)[::-1].hex()
        prev_vout = struct.unpack('<I', read_bytes(4))[0]
        script_sig = read_varbytes().hex()
        sequence = struct.unpack('<I', read_bytes(4))[0]
        vin.append({
            'txid': prev_txid,
            'vout': prev_vout,
            'scriptSig': script_sig,
            'sequence': sequence
        })

    vout = []
    vout_count = read_varint()
    for i in range(vout_count):
        value = read_uint64()
        script_pubkey = read_varbytes().hex()
        vout.append({
            'value_sats': value,
            'value_btc': value / 1e8,
            'scriptPubKey': script_pubkey
        })

    witnesses: List[List[str]] = []
    if is_segwit:
        for i in range(vin_count):
            item_count = read_varint()
            items = []
            for j in range(item_count):
                item = read_varbytes().hex()
                items.append(item)
            witnesses.append(items)

    locktime = read_uint32()

    parsed = {
        'version': version,
        'is_segwit': is_segwit,
        'vin': vin,
        'vout': vout,
        'witnesses': witnesses if is_segwit else None,
        'locktime': locktime
    }

 
    def encode_varint(i: int) -> bytes:
        if i < 0xfd:
            return bytes([i])
        if i <= 0xffff:
            return b'\xfd' + struct.pack('<H', i)
        if i <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', i)
        return b'\xff' + struct.pack('<Q', i)

  
    def serialize_no_witness(p: Dict[str, Any]) -> bytes:
        tx = bytearray()
        tx += struct.pack('<I', p['version'])
        tx += encode_varint(len(p['vin']))
        for inp in p['vin']:
            tx += bytes.fromhex(inp['txid'])[::-1]
            tx += struct.pack('<I', inp['vout'])
            script = bytes.fromhex(inp['scriptSig'])
            tx += encode_varint(len(script))
            tx += script
            tx += struct.pack('<I', inp['sequence'])
        tx += encode_varint(len(p['vout']))
        for out in p['vout']:
            tx += struct.pack('<Q', out['value_sats'])
            script = bytes.fromhex(out['scriptPubKey'])
            tx += encode_varint(len(script))
            tx += script
        tx += struct.pack('<I', p['locktime'])
        return bytes(tx)

    raw_full = bytes.fromhex(hex_tx)
    hash_full = hashlib.sha256(hashlib.sha256(raw_full).digest()).digest()[::-1].hex()
    try:
        raw_no_wit = serialize_no_witness(parsed)
        hash_no_wit = hashlib.sha256(hashlib.sha256(raw_no_wit).digest()).digest()[::-1].hex()
    except Exception:
        hash_no_wit = hash_full

    parsed['txid_computed'] = hash_no_wit
    parsed['wtxid_computed'] = hash_full

    return parsed


if __name__ == '__main__':
    tx_hex = ("0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000"
              "fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c081000000000001"
              "60014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a"
              "530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97"
              "dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00")

    parsed = decode_tx(tx_hex)
    print('--- Parsed JSON ---')
    print(json.dumps(parsed, indent=2))
    print('\n--- Short summary ---')
    print(f"Version: {parsed['version']}")
    print(f"SegWit: {parsed['is_segwit']}")
    print(f"Inputs: {len(parsed['vin'])}")
    for i, inp in enumerate(parsed['vin']):
        print(f" Input {i}: txid={inp['txid']} vout={inp['vout']} sequence={hex(inp['sequence'])}")
        if inp['scriptSig']:
            print(f"  scriptSig (hex len={len(inp['scriptSig'])//2}): {inp['scriptSig']}")
    print(f"Outputs: {len(parsed['vout'])}")
    for i, out in enumerate(parsed['vout']):
        print(f" Output {i}: {out['value_sats']} sats ({out['value_btc']} BTC)")
        print(f"  scriptPubKey hex (len={len(out['scriptPubKey'])//2}): {out['scriptPubKey']}")
    if parsed['is_segwit']:
        print('Witnesses present:')
        for i, w in enumerate(parsed['witnesses']):
            print(f" Input {i} witness items: {len(w)}")
            for j, it in enumerate(w):
                print(f"  [{j}] len={len(it)//2} hex={it}")
    print(f"Locktime: {parsed['locktime']} (hex {parsed['locktime']:08x})")
    print(f"txid (computed): {parsed['txid_computed']}")
    print(f"wtxid (computed): {parsed['wtxid_computed']}")
