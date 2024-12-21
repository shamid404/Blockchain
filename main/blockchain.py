import time

class SHA256:
    def __init__(self):
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0x8e44a1d6, 0x90bdc0b1, 0x8a4423e5, 0x584b6b8f, 0x6d6d5ecf, 0x7a4b17e3, 0x7f2c6b8f, 0x88c3f83b,
            0x8831c1a6, 0x8a04b9db, 0x5a305e3, 0x0b5e1eaf, 0x2b90b8b7, 0x2eb38a3a, 0x31c370b5, 0x311e7e3e,
            0x6c44198c, 0x64b8985c, 0x2a3e4c9b, 0x017ec92a, 0x74c49724, 0x358cde39, 0x48cf7cc2, 0x74cc15b6,
            0x8b45038a, 0x5c542d3a, 0x94b5d08e, 0x60b4d6d7, 0x0d5394fd, 0xdfe7d905, 0x3f76f8dd, 0x1f30e38d,
            0x1b0c9b80, 0x1c798225, 0x4654650b, 0x4f3190da, 0x9ea875f0, 0x0a875c66, 0x5b2b4660, 0x16c5f88c,
            0x4e07aa98, 0x1eec6f98, 0x59a021a8, 0x97e5b4a6, 0x367f0b1d, 0xa19b4025, 0x4730be0d, 0x2b42a7e5
        ]
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.pad = 0x80
    def right_rotate(self, x, n):
        return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

    def sha256(self, msg: str) -> str:
        message = bytearray(msg, 'utf-8')
        message_len = len(message) * 8
        message.append(self.pad)

        while (len(message) * 8) % 512 != 448:
            message.append(0)

        for i in range(8):
            message.append((message_len >> (8 * (7 - i))) & 0xFF)

        for i in range(0, len(message), 64):
            block = message[i:i + 64]
            w = [0] * 64
            for j in range(16):
                w[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) | (block[j * 4 + 2] << 8) | block[j * 4 + 3]

            for j in range(16, 64):
                s0 = self.right_rotate(w[j - 15], 7) ^ self.right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
                s1 = self.right_rotate(w[j - 2], 17) ^ self.right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = self.h

            for j in range(64):
                s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + s1 + ch + self.k[j] + w[j]) & 0xFFFFFFFF
                s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF
            self.h = [(x + y) & 0xFFFFFFFF for x, y in zip(self.h, [a, b, c, d, e, f, g, h])]

        return ''.join([f'{x:08x}' for x in self.h])


def calculate_merkle_root(transactions: list) -> str:
    if len(transactions) == 1:
        return SHA256().sha256(transactions[0])
    while len(transactions) > 1:
        temp_transactions = []
        for i in range(0, len(transactions), 2):
            if i + 1 < len(transactions):
                temp_transactions.append(SHA256().sha256(transactions[i] + transactions[i + 1]))
            else:
                temp_transactions.append(SHA256().sha256(transactions[i] + transactions[i]))
        transactions = temp_transactions
    return transactions[0]

class Block:
    def __init__(self, previous_hash: str, timestamp: float, transactions: list):
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = calculate_merkle_root(transactions)
        self.hash = self.mine_block()

    def mine_block(self, difficulty: int = 4) -> str:
        nonce = 0
        sha256 = SHA256()
        while True:
            block_data = f'{self.previous_hash}{self.timestamp}{self.merkle_root}{nonce}'
            block_hash = sha256.sha256(block_data)
            if block_hash[:difficulty] == '0' * difficulty:
                return block_hash
            nonce += 1

    def __str__(self):
        return f"Hash: {self.hash}\nPrevious Hash: {self.previous_hash}\nMerkle Root: {self.merkle_root}\nTimestamp: {self.timestamp}\n"


class Blockchain:
    def __init__(self):
        self.chain = []
        self.add_genesis_block()

    def add_genesis_block(self):
        genesis_block = Block("0", time.time(), ["Initial transaction"])
        self.chain.append(genesis_block)

    def add_block(self, transactions: list):
        previous_block = self.chain[-1]
        new_block = Block(previous_block.hash, time.time(), transactions)
        self.chain.append(new_block)

    def validate_blockchain(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.mine_block():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

print("Mining block...")

blockchain = Blockchain()

blockchain.add_block(["Alice sends 10 BTC to Bob"])

print("Blockchain valid:", blockchain.validate_blockchain())

# Вывод всех блоков
for block in blockchain.chain:
    print(block)
