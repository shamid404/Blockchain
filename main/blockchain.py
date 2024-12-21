import hashlib
import time

def hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.tree = self.build_merkle_tree(transactions)

    def build_merkle_tree(self, transactions):
        tree = []
        for tx in transactions:
            tree.append(hash(tx))
        
        while len(tree) > 1:
            temp = []
            for i in range(0, len(tree), 2):
                if i+1 < len(tree):
                    combined = tree[i] + tree[i+1]
                else:
                    combined = tree[i] + tree[i]  # Handle odd number of elements
                temp.append(hash(combined))
            tree = temp
        
        return tree[0]

class Block:
    def __init__(self, previous_hash, timestamp, merkle_root):
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.merkle_root = merkle_root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return hash(f"{self.previous_hash}{self.timestamp}{self.merkle_root}")

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        timestamp = str(int(time.time()))
        merkle_tree = MerkleTree(["Transaction1", "Transaction2", "Transaction3", "Transaction4", "Transaction5", "Transaction6", "Transaction7", "Transaction8", "Transaction9", "Transaction10"])
        genesis_block = Block("0", timestamp, merkle_tree.tree)
        self.chain.append(genesis_block)

    def mine_block(self, transactions):
        timestamp = str(int(time.time()))
        merkle_tree = MerkleTree(transactions)
        previous_block = self.chain[-1]
        block = Block(previous_block.hash, timestamp, merkle_tree.tree)
        self.chain.append(block)

    def validate_blockchain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def print_chain(self):
        for block in self.chain:
            print(f"Block Hash: {block.hash}")
            print(f"Previous Block Hash: {block.previous_hash}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Merkle Root: {block.merkle_root}")
            print("===================================")

# Example usage
blockchain = Blockchain()

transactions = [
    "Sender1 -> Receiver1: 100",
    "Sender2 -> Receiver2: 50",
    "Sender3 -> Receiver3: 200",
    "Sender4 -> Receiver4: 150",
    "Sender5 -> Receiver5: 300",
    "Sender6 -> Receiver6: 500",
    "Sender7 -> Receiver7: 800",
    "Sender8 -> Receiver8: 400",
    "Sender9 -> Receiver9: 250",
    "Sender10 -> Receiver10: 100"
]
blockchain.mine_block(transactions)

if blockchain.validate_blockchain():
    print("Blockchain is valid!")
else:
    print("Blockchain is invalid.")

blockchain.print_chain()
