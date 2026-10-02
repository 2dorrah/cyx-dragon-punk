import hashlib
import json
import time
import zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
try:
    from blake3 import blake3
    BLAKE3_BACKEND = 'blake3'
except ImportError:
    from hashlib import blake2b as _blake2b

    class _B2:

        def __init__(self, data=b''):
            self._data = data

        def digest(self, length=32):
            return _blake2b(self._data, digest_size=length).digest()

    def blake3(data=b''):
        return _B2(data)
    BLAKE3_BACKEND = 'blake2b-fallback'
'\nCYTHAN MAINNET\nExperimental standalone proof-of-work blockchain.\n\nP2P:\n    0.0.0.0:8443\n\nLOCAL CONTROL:\n    127.0.0.1:8444\n\nPython:\n    3.10+\n\nDependency:\n    pip install blake3\n'
NETWORK = 'CYTHAN-MAINNET'
VERSION = '1.0.0'
CHAIN_ID = 'CYTHAN-01'
P2P_PROTOCOL = 'CYTHAN/1'
DATA_DIR = Path('data/cythan_mainnet')
CHAIN_FILE = DATA_DIR / 'chain.json'
STATE_FILE = DATA_DIR / 'state.json'
P2P_HOST = '0.0.0.0'
P2P_PORT = 8443
CONTROL_HOST = '127.0.0.1'
CONTROL_PORT = 8444
TARGET_BLOCK_TIME = 60
BLOCK_INTERVAL = TARGET_BLOCK_TIME
DIFFICULTY_WINDOW = 60
INITIAL_REWARD = 50
HALVING_INTERVAL = 210000
MAX_MONEY = 10500000
SCRYPT_N = 1024
SCRYPT_R = 1
SCRYPT_P = 1
SCRYPT_DKLEN = 32
INITIAL_TARGET = int('0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)
MAX_TARGET = INITIAL_TARGET
VECTOR_KEY = b'CYTHAN-MAINNET-V1'
CYTHAN_ADDRESS_VERSION = b'<'
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
MINER_ADDRESS = 'CYTHAN-MINER'
RUNNING = True

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))

def blake3_256(data: bytes) -> bytes:
    return blake3(data).digest(length=32)

def scrypt256(data: bytes, salt: bytes | None=None) -> bytes:
    if salt is None:
        salt = data
    return hashlib.scrypt(password=data, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)

def pbkdf2_sha512(data: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', data, salt, 2048, 64)

def joaat(data: bytes) -> int:
    h = 0
    for byte in data:
        h = h + byte & 4294967295
        h = h + (h << 10 & 4294967295) & 4294967295
        h ^= h >> 6
    h = h + (h << 3 & 4294967295) & 4294967295
    h ^= h >> 11
    h = h + (h << 15 & 4294967295) & 4294967295
    return h & 4294967295

def cythan_vector() -> dict:
    vector = blake3_256(b'CYTHAN|VECTOR|' + CHAIN_ID.encode() + b'|' + VECTOR_KEY)
    return {'vector': vector, 'joaat': joaat(vector)}

def cythanize(payload: bytes, previous: bytes=b'\x00' * 32) -> dict:
    vector_data = cythan_vector()
    vector = vector_data['vector']
    vector_joaat = vector_data['joaat']
    joaat_bytes = vector_joaat.to_bytes(4, 'big')
    state = blake3_256(b'CYTHAN|STATE|' + payload + previous + vector + joaat_bytes)
    sha_state = double_sha256(b'CYTHAN|SHA256|' + state)
    scrypt_state = scrypt256(b'CYTHAN|SCRYPT|' + sha_state)
    commitment = blake3_256(b'CYTHAN|COMMITMENT|' + vector + joaat_bytes + state + sha_state + scrypt_state)
    return {'vector': vector.hex(), 'joaat': f'{vector_joaat:08x}', 'state': state.hex(), 'sha256': sha_state.hex(), 'scrypt': scrypt_state.hex(), 'commitment': commitment.hex()}

def transmogrify(payload: bytes, previous: bytes=b'\x00' * 32) -> dict:
    first = cythanize(payload, previous)
    transformed = canonical({'type': 'CYTHAN-TRANSMOGRIFICATION', 'network': NETWORK, 'chain_id': CHAIN_ID, 'input': payload.hex(), 'cythan': first})
    second = cythanize(transformed, bytes.fromhex(first['commitment']))
    return {'type': 'TRANSMOGRIFIED-CYTHAN', 'input': payload.hex(), 'first': first, 'final': second}

def joatt(payload: bytes, previous_state: bytes=b'\x00' * 32) -> dict:
    b3_state = blake3_256(b'JOATT|BLAKE3|' + CHAIN_ID.encode() + previous_state + payload)
    root = double_sha256(b'JOATT|ROOT|' + previous_state + b3_state + payload)
    pbkdf = pbkdf2_sha512(root, b'JOATT|PBKDF2|' + CHAIN_ID.encode())
    scrypt_state = scrypt256(pbkdf, salt=b'JOATT|SCRYPT|' + CHAIN_ID.encode())
    mixed = blake3_256(b'JOATT|MIX|' + b3_state + root + pbkdf + scrypt_state)
    checksum = blake3_256(b'JOATT|CHECKSUM|' + mixed + root + scrypt_state)[:4]
    identifier64 = blake3_256(b'JOATT|ID64|' + checksum + mixed + previous_state)[:8]
    adler = zlib.adler32(mixed) & 4294967295
    state256 = blake3_256(b'JOATT|STATE256|' + b3_state + root + pbkdf + scrypt_state + mixed + checksum + identifier64 + adler.to_bytes(4, 'big'))
    return {'blake3': b3_state.hex(), 'root': root.hex(), 'pbkdf2': pbkdf.hex(), 'scrypt': scrypt_state.hex(), 'mix': mixed.hex(), 'checksum': checksum.hex(), 'identifier64': identifier64.hex(), 'adler32': f'{adler:08x}', 'state256': state256.hex()}

def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, 'big')
    encoded = ''
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    zeroes = len(data) - len(data.lstrip(b'\x00'))
    return '1' * zeroes + encoded

def base58_decode(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in BASE58_ALPHABET:
            raise ValueError('invalid Base58 character')
        number = number * 58 + BASE58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b''
    zeroes = len(value) - len(value.lstrip('1'))
    return b'\x00' * zeroes + raw

def address_checksum(payload: bytes) -> bytes:
    return blake3_256(b'CYTHAN|ADDRESS|' + payload)[:4]

def address_from_pubkey(pubkey: bytes) -> str:
    digest = hashlib.sha256(pubkey).digest()
    ripemd = hashlib.new('ripemd160')
    ripemd.update(digest)
    key_hash = ripemd.digest()
    payload = CYTHAN_ADDRESS_VERSION + key_hash
    return base58_encode(payload + address_checksum(payload))

def validate_address(address: str) -> bool:
    try:
        raw = base58_decode(address)
        if len(raw) != 25:
            return False
        payload = raw[:-4]
        checksum = raw[-4:]
        if payload[:1] != CYTHAN_ADDRESS_VERSION:
            return False
        return checksum == address_checksum(payload)
    except Exception:
        return False

def transaction_id(transaction: dict) -> str:
    body = dict(transaction)
    body.pop('txid', None)
    return double_sha256(canonical(body)).hex()

def make_transaction(sender: str, recipient: str, amount: int) -> dict:
    if amount <= 0:
        raise ValueError('amount must be positive')
    if not validate_address(recipient):
        raise ValueError('invalid recipient address')
    tx = {'sender': sender, 'recipient': recipient, 'amount': amount, 'timestamp': time.time()}
    tx['txid'] = transaction_id(tx)
    return tx

@dataclass
class Block:
    height: int
    timestamp: int
    previous_hash: str
    transactions: list
    target: str
    cythan_commitment: str
    joatt_state: str
    joatt_identifier: str
    nonce: int = 0
    hash: str = ''

    def header(self) -> dict:
        return {'height': self.height, 'timestamp': self.timestamp, 'previous_hash': self.previous_hash, 'transactions': self.transactions, 'target': self.target, 'cythan_commitment': self.cythan_commitment, 'joatt_state': self.joatt_state, 'joatt_identifier': self.joatt_identifier, 'nonce': self.nonce}

    def hash_bytes(self) -> bytes:
        header = canonical(self.header())
        return scrypt256(header, salt=header)

    def calculate_hash(self) -> str:
        return self.hash_bytes().hex()

    def mine(self) -> bool:
        target = int(self.target, 16)
        while RUNNING:
            digest = self.hash_bytes()
            if int.from_bytes(digest, 'big') <= target:
                self.hash = digest.hex()
                return True
            self.nonce += 1
        return False

class CythanMainnet:

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.chain: list[Block] = []
        self.pending: list[dict] = []
        if CHAIN_FILE.exists():
            self.load()
            if not self.validate():
                raise RuntimeError('stored chain validation failed')
            print('[CHAIN] loaded')
        else:
            self.create_genesis()

    @property
    def latest(self) -> Block:
        return self.chain[-1]

    def current_target(self) -> int:
        if len(self.chain) <= 1:
            return INITIAL_TARGET
        if len(self.chain) - 1 < DIFFICULTY_WINDOW:
            return int(self.latest.target, 16)
        window = self.chain[-DIFFICULTY_WINDOW:]
        actual = max(1, window[-1].timestamp - window[0].timestamp)
        expected = TARGET_BLOCK_TIME * (DIFFICULTY_WINDOW - 1)
        ratio = actual / expected
        ratio = max(0.25, min(4.0, ratio))
        old_target = int(self.latest.target, 16)
        new_target = int(old_target * ratio)
        return max(1, min(MAX_TARGET, new_target))

    def block_reward(self, height: int) -> int:
        halvings = height // HALVING_INTERVAL
        if halvings >= 63:
            return 0
        return INITIAL_REWARD >> halvings

    def create_genesis(self):
        payload = canonical({'network': NETWORK, 'version': VERSION, 'chain_id': CHAIN_ID, 'message': 'CYTHAN MAINNET GENESIS', 'timestamp': 0, 'supply': 0, 'consensus': 'SCRYPT'})
        cythan = cythanize(payload)
        transformed = transmogrify(payload, bytes.fromhex(cythan['commitment']))
        state = joatt(canonical(transformed))
        block = Block(height=0, timestamp=0, previous_hash='00' * 32, transactions=[{'type': 'GENESIS', 'network': NETWORK, 'chain_id': CHAIN_ID, 'message': 'CYTHAN MAINNET GENESIS'}], target=f'{INITIAL_TARGET:064x}', cythan_commitment=transformed['final']['commitment'], joatt_state=state['state256'], joatt_identifier=state['identifier64'])
        block.hash = block.calculate_hash()
        self.chain = [block]
        self.save()
        self.save_state(state)
        print('[GENESIS]', block.hash)

    def balance(self, address: str) -> int:
        total = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('type') == 'MINING_REWARD':
                    if tx.get('recipient') == address:
                        total += tx['amount']
                    continue
                if tx.get('sender') == address:
                    total -= tx['amount']
                if tx.get('recipient') == address:
                    total += tx['amount']
        return total

    def validate_transactions(self, transactions: list, height: int) -> bool:
        reward_count = 0
        for tx in transactions:
            if tx.get('type') == 'MINING_REWARD':
                reward_count += 1
                if reward_count > 1:
                    return False
                if tx.get('sender') != NETWORK:
                    return False
                if tx.get('amount') != self.block_reward(height):
                    return False
                continue
            sender = tx.get('sender')
            recipient = tx.get('recipient')
            amount = tx.get('amount')
            if not isinstance(sender, str):
                return False
            if not isinstance(recipient, str):
                return False
            if not validate_address(recipient):
                return False
            if not isinstance(amount, int):
                return False
            if amount <= 0:
                return False
        return True

    def build_state(self, transactions):
        previous_commitment = bytes.fromhex(self.latest.cythan_commitment)
        previous_state = bytes.fromhex(self.latest.joatt_state)
        payload = canonical({'height': len(self.chain), 'previous_hash': self.latest.hash, 'transactions': transactions, 'network': NETWORK, 'chain_id': CHAIN_ID})
        first = cythanize(payload, previous_commitment)
        transformed = transmogrify(payload, bytes.fromhex(first['commitment']))
        state_payload = canonical({'transformed': transformed, 'previous_hash': self.latest.hash, 'height': len(self.chain)})
        state = joatt(state_payload, previous_state)
        return (transformed['final'], state)

    def mine_block(self) -> bool:
        height = len(self.chain)
        reward = self.block_reward(height)
        transactions = list(self.pending)
        transactions.append({'type': 'MINING_REWARD', 'sender': NETWORK, 'recipient': MINER_ADDRESS, 'amount': reward, 'timestamp': int(time.time())})
        if not self.validate_transactions(transactions, height):
            raise RuntimeError('invalid transaction set')
        cythan, state = self.build_state(transactions)
        target = self.current_target()
        block = Block(height=height, timestamp=int(time.time()), previous_hash=self.latest.hash, transactions=transactions, target=f'{target:064x}', cythan_commitment=cythan['commitment'], joatt_state=state['state256'], joatt_identifier=state['identifier64'])
        print(f'[MINING] height={height} target={block.target}')
        started = time.monotonic()
        if not block.mine():
            return False
        elapsed = time.monotonic() - started
        self.chain.append(block)
        self.pending.clear()
        self.save()
        self.save_state(state)
        print(f'[BLOCK] {block.height} nonce={block.nonce} time={elapsed:.3f}s')
        print('[HASH]', block.hash)
        return True

    def validate(self) -> bool:
        if not self.chain:
            return False
        genesis = self.chain[0]
        if genesis.height != 0:
            return False
        if genesis.previous_hash != '00' * 32:
            return False
        if genesis.hash != genesis.calculate_hash():
            return False
        for index in range(1, len(self.chain)):
            current = self.chain[index]
            previous = self.chain[index - 1]
            if current.height != index:
                return False
            if current.previous_hash != previous.hash:
                return False
            if current.hash != current.calculate_hash():
                return False
            if int(current.hash, 16) > int(current.target, 16):
                return False
            if not self.validate_transactions(current.transactions, current.height):
                return False
        return True

    def save(self):
        data = {'network': NETWORK, 'version': VERSION, 'chain_id': CHAIN_ID, 'protocol': P2P_PROTOCOL, 'chain': [asdict(block) for block in self.chain]}
        temporary = CHAIN_FILE.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, indent=2), encoding='utf-8')
        temporary.replace(CHAIN_FILE)

    def save_state(self, state):
        data = {'network': NETWORK, 'chain_id': CHAIN_ID, 'timestamp': time.time(), 'state': state}
        temporary = STATE_FILE.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, indent=2), encoding='utf-8')
        temporary.replace(STATE_FILE)

    def load(self):
        data = json.loads(CHAIN_FILE.read_text(encoding='utf-8'))
        if data.get('network') != NETWORK:
            raise RuntimeError('network mismatch')
        if data.get('chain_id') != CHAIN_ID:
            raise RuntimeError('chain ID mismatch')
        self.chain = [Block(**block) for block in data['chain']]

def automate():
    """Run the CYTHAN miner continuously with no interactive command/control server."""
    global RUNNING
    chain = CythanMainnet()
    vector = cythan_vector()
    print('=' * 72)
    print('CYTHAN CONVERGED AUTOMATED MINER')
    print('=' * 72)
    print(f'Network       : {NETWORK}')
    print(f'Version       : {VERSION}')
    print(f'Chain ID      : {CHAIN_ID}')
    print('Mode          : LOCAL AUTOMATED MINING')
    print('PoW           : Scrypt')
    print(f'Scrypt        : N={SCRYPT_N} r={SCRYPT_R} p={SCRYPT_P}')
    print(f'Block time    : {TARGET_BLOCK_TIME}s')
    print(f'Reward        : {INITIAL_REWARD}')
    print(f'Halving       : {HALVING_INTERVAL}')
    print(f'Data          : {DATA_DIR}')
    print(f"JOAAT         : {vector['joaat']:08x}")
    print(f'BLAKE3        : {BLAKE3_BACKEND}')
    print('=' * 72)
    try:
        while RUNNING:
            if not chain.validate():
                raise RuntimeError('CHAIN VALIDATION FAILED')
            block_start = time.monotonic()
            print(f'[CHAIN] height={len(chain.chain) - 1}')
            if not chain.mine_block():
                if RUNNING:
                    raise RuntimeError('MINING STOPPED')
                break
            if not chain.validate():
                raise RuntimeError('POST-MINING VALIDATION FAILED')
            print(f'[VALID] height={len(chain.chain) - 1}')
            elapsed = time.monotonic() - block_start
            remaining = max(0.0, BLOCK_INTERVAL - elapsed)
            if remaining:
                time.sleep(remaining)
    except KeyboardInterrupt:
        RUNNING = False
        print('\n[STOP] miner interrupted')
    finally:
        try:
            chain.save()
        except Exception as error:
            print('[SAVE ERROR]', error)
        print(f'[STOPPED] final height={len(chain.chain) - 1}')
if __name__ == '__main__':
    automate()
