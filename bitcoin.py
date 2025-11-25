"""
A simplified Bitcoin-like blockchain system with a graphical interface.

This program implements the core elements of a very small cryptocurrency: key
generation, address creation, transaction signing/verification, block
construction, a proof-of-work based mining mechanism, and chain validation.  A
Tkinter GUI ties these pieces together allowing you to create wallets, send
funds, mine pending transactions into new blocks, explore the chain, and
query balances.  The entire application is contained in a single file for
Ease of deployment and demonstration.

Dependencies:

- Python 3.  The code only uses the standard library and the `cryptography`
  package for elliptic curve operations.
- The `cryptography` package.  Install it via `pip install cryptography` if
  it's not already available.

Running the program will open a window with buttons and fields for each
functionality.  You can generate new wallets, copy your private keys and
addresses, sign and submit transactions, mine blocks to earn rewards and
confirm transactions, inspect the blockchain and unconfirmed transactions,
and query balances by address.
"""

import hashlib
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import filedialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keys():
    """Generate a new ECDSA private/public key pair on the secp256k1 curve."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key


def address_from_public(public_key):
    """
    Derive a simple address from a public key.

    We serialize the public key in uncompressed X9.62 form, hash it with
    SHA-256 and take the first 20 bytes (40 hexadecimal characters) as the
    address.  This is **not** a full Bitcoin address (which would involve
    additional hashing and encoding) but suffices for our simplified system.
    """
    # Uncompressed point: 0x04 || X || Y
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    sha = hashlib.sha256(public_bytes).hexdigest()
    # Return first 40 hex characters (20 bytes) as the address
    return sha[:40]


class Transaction:
    """
    A transaction transferring an amount from one address to another.

    Each transaction stores the sender's address, recipient's address, amount,
    a timestamp, the sender's public key (so that the signature can be
    verified) and the signature itself.  Transactions are signed over a
    canonical string representation of their contents.
    """

    def __init__(self, sender, recipient, amount, timestamp=None, sender_public_key_hex=None, signature=None):
        self.sender = sender  # address string or "MINING" for rewards
        self.recipient = recipient  # address string
        self.amount = amount  # numeric amount
        self.timestamp = timestamp or time.time()
        # The sender's public key serialized as a hex string (uncompressed)
        self.sender_public_key = sender_public_key_hex
        # Signature stored as hex string
        self.signature = signature

    def to_dict(self):
        """Return a dictionary representation of the transaction for hashing or JSON."""
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'sender_public_key': self.sender_public_key,
            'signature': self.signature,
        }

    def compute_hash(self):
        """Compute a SHA256 hash of the transaction contents (excluding the signature)."""
        # Use a deterministic string representation of the transaction
        tx_contents = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_contents.encode()).hexdigest()

    def sign_transaction(self, private_key):
        """
        Sign the transaction with the given private key.

        The sender address and public key are derived from the private key.  If
        the transaction already has a sender field set, it is checked to
        ensure the provided private key corresponds to that address.
        """
        # Derive the public key and address from the private key
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        derived_address = address_from_public(public_key)
        # If sender has been set, ensure it matches the key used for signing
        if self.sender != "MINING" and self.sender and self.sender != derived_address:
            raise ValueError("Private key does not match the sender's address.")
        self.sender = derived_address
        # Store the public key for verification
        self.sender_public_key = pub_bytes.hex()
        # Create the message to sign
        message = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}".encode()
        # Sign with ECDSA and SHA256
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        # Store signature as hex string
        self.signature = signature.hex()

    def is_valid(self):
        """
        Verify the transaction's signature and fields.

        Mining reward transactions (with sender == "MINING") are considered
        valid automatically.  For all others, both a signature and a
        sender_public_key must be present.  The signature is verified against
        the computed message and the derived address is compared with the
        sender field.
        """
        # Coinbase or reward transactions do not require a signature
        if self.sender == "MINING":
            return True
        if not self.signature or not self.sender_public_key:
            return False
        try:
            # Recreate the public key from the hex string
            pub_bytes = bytes.fromhex(self.sender_public_key)
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
            # Recompute the sender address from the public key
            derived_address = address_from_public(public_key)
            if derived_address != self.sender:
                return False
            # Verify signature
            message = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}".encode()
            signature_bytes = bytes.fromhex(self.signature)
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class Block:
    """
    A single block in the blockchain.

    Each block contains an index, a timestamp, a list of transactions, the
    hash of the previous block, a nonce for proof-of-work, and its own hash.
    The hash is computed over the block's contents (including the
    simplified Merkle root derived from the transactions) and the nonce.
    """

    def __init__(self, index, transactions, previous_hash, timestamp=None, nonce=0, block_hash=None):
        self.index = index
        self.transactions = transactions  # list of Transaction objects
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.hash = block_hash or self.compute_hash()

    def compute_hash(self):
        """
        Compute the block's hash.

        The transactions are represented by concatenating their transaction
        hashes (not the signatures) to form a very simple 'Merkle root'.  The
        block's index, timestamp, previous hash, transactions string and
        nonce are concatenated and hashed with SHA256.
        """
        tx_string = ''.join([tx.compute_hash() for tx in self.transactions])
        block_string = f"{self.index}{self.timestamp}{self.previous_hash}{tx_string}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    """
    The main blockchain structure containing a list of blocks and unconfirmed
    transactions.

    It supports adding new transactions, mining them into new blocks via
    proof-of-work, checking the validity of the chain, and computing
    balances.
    """

    def __init__(self, difficulty=4, reward=50):
        self.difficulty = difficulty  # number of leading zeroes required
        self.reward = reward  # mining reward
        self.unconfirmed_transactions = []  # pending transactions
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block in the blockchain, known as the genesis block."""
        # A single reward transaction to a dummy address opens the chain
        genesis_tx = Transaction("MINING", "", 0)
        genesis_block = Block(0, [genesis_tx], "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    def add_new_transaction(self, transaction):
        """
        Add a verified transaction to the pool of unconfirmed transactions.

        If the transaction is invalid or the sender's balance is insufficient,
        an exception is raised and the transaction is not added.
        """
        if not transaction.is_valid():
            raise ValueError("Invalid transaction: signature could not be verified.")
        # Skip balance check for coinbase/mining reward transactions
        if transaction.sender != "MINING":
            sender_balance = self.get_balance(transaction.sender)
            # Count pending outgoing amounts as well
            for tx in self.unconfirmed_transactions:
                if tx.sender == transaction.sender:
                    sender_balance -= tx.amount
            if sender_balance < transaction.amount:
                raise ValueError("Insufficient funds for this transaction.")
        self.unconfirmed_transactions.append(transaction)

    def proof_of_work(self, block):
        """
        Perform a proof-of-work on the provided block.

        Increment the nonce until the block's hash has the requisite number of
        leading zeroes.  Once a valid nonce is found, the block's hash is
        updated and returned.
        """
        computed_hash = block.compute_hash()
        target = '0' * self.difficulty
        while not computed_hash.startswith(target):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def mine(self, miner_address):
        """
        Mine pending transactions into a new block and award the miner.

        Even if there are no user transactions, we still allow mining an
        empty block that only contains the mining reward. This avoids the
        “no coins exist so nobody can ever send a transaction” deadlock.
        """
        # Always create a reward transaction for the miner
        reward_tx = Transaction("MINING", miner_address, self.reward)
        # All transactions to be included in this block:
        #   mining reward + current unconfirmed transactions
        txs = [reward_tx] + self.unconfirmed_transactions[:]

        new_block = Block(
            index=len(self.chain),
            transactions=txs,
            previous_hash=self.chain[-1].hash,
        )

        # Perform proof-of-work
        new_block.hash = self.proof_of_work(new_block)

        # Append the block and clear the unconfirmed pool
        self.chain.append(new_block)
        self.unconfirmed_transactions = []

        return new_block

    def is_chain_valid(self):
        """Check the entire blockchain for validity."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]
            # Check that the stored hash is valid
            if current.hash != current.compute_hash():
                return False
            # Check linkage
            if current.previous_hash != prev.hash:
                return False
            # Check proof of work
            if not current.hash.startswith('0' * self.difficulty):
                return False
            # Check all transactions in the block
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
        return True

    def get_balance(self, address):
        """Calculate the balance for a given address by scanning the chain."""
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        # Also subtract any pending outgoing transactions
        for tx in self.unconfirmed_transactions:
            if tx.sender == address:
                balance -= tx.amount
        return balance


class BlockchainGUI:
    """
    The graphical interface wrapping around the blockchain.

    Provides controls for generating keys, creating and submitting transactions,
    mining pending transactions, viewing chain data, and querying balances.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Simplified Bitcoin System")
        # Underlying blockchain instance
        self.blockchain = Blockchain(difficulty=4, reward=50)
        # Build the UI
        self.create_widgets()

    def create_widgets(self):
        """Create and lay out all widgets in the main window."""
        # Use a notebook (tabs) to group functionality
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')

        # Wallet tab
        self.wallet_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.wallet_frame, text="Wallets")
        self.create_wallet_tab(self.wallet_frame)

        # Transaction tab
        self.tx_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tx_frame, text="Transactions")
        self.create_transaction_tab(self.tx_frame)

        # Mining tab
        self.mining_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.mining_frame, text="Mining")
        self.create_mining_tab(self.mining_frame)

        # Chain tab
        self.chain_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.chain_frame, text="Blockchain")
        self.create_chain_tab(self.chain_frame)

        # Balance tab
        self.balance_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.balance_frame, text="Balances")
        self.create_balance_tab(self.balance_frame)

    def create_wallet_tab(self, frame):
        """Build the wallet generation interface."""
        label = ttk.Label(frame, text="Generate a new wallet (key pair and address)")
        label.pack(pady=5)
        generate_btn = ttk.Button(frame, text="Create Wallet", command=self.generate_wallet)
        generate_btn.pack(pady=5)
        self.wallet_output = scrolledtext.ScrolledText(frame, width=80, height=15, state='disabled')
        self.wallet_output.pack(padx=10, pady=5, fill='both', expand=True)

    def create_transaction_tab(self, frame):
        """Build the transaction creation interface."""
        ttk.Label(frame, text="Create and sign a new transaction").pack(pady=5)
        # Sender private key input
        ttk.Label(frame, text="Sender private key (PEM)").pack(anchor='w', padx=10)
        self.sender_priv_key_text = scrolledtext.ScrolledText(frame, width=80, height=7)
        self.sender_priv_key_text.pack(padx=10, pady=3, fill='x')
        # Recipient address
        ttk.Label(frame, text="Recipient address").pack(anchor='w', padx=10)
        self.recipient_entry = ttk.Entry(frame, width=80)
        self.recipient_entry.pack(padx=10, pady=3, fill='x')
        # Amount
        ttk.Label(frame, text="Amount").pack(anchor='w', padx=10)
        self.amount_entry = ttk.Entry(frame, width=20)
        self.amount_entry.pack(padx=10, pady=3, anchor='w')
        # Submit button
        send_btn = ttk.Button(frame, text="Submit Transaction", command=self.submit_transaction)
        send_btn.pack(pady=5)
        # Output area
        self.tx_output = scrolledtext.ScrolledText(frame, width=80, height=8, state='disabled')
        self.tx_output.pack(padx=10, pady=5, fill='both', expand=True)

    def create_mining_tab(self, frame):
        """Build the mining interface."""
        ttk.Label(frame, text="Mine pending transactions into a new block").pack(pady=5)
        ttk.Label(frame, text="Your miner address (from generated wallet)").pack(anchor='w', padx=10)
        self.miner_address_entry = ttk.Entry(frame, width=80)
        self.miner_address_entry.pack(padx=10, pady=3, fill='x')
        mine_btn = ttk.Button(frame, text="Mine Block", command=self.mine_block)
        mine_btn.pack(pady=5)
        self.mining_output = scrolledtext.ScrolledText(frame, width=80, height=10, state='disabled')
        self.mining_output.pack(padx=10, pady=5, fill='both', expand=True)

    def create_chain_tab(self, frame):
        """Build the blockchain viewing interface."""
        ttk.Label(frame, text="Current blockchain").pack(pady=5)
        self.chain_text = scrolledtext.ScrolledText(frame, width=100, height=25, state='disabled')
        self.chain_text.pack(padx=10, pady=5, fill='both', expand=True)
        refresh_btn = ttk.Button(frame, text="Refresh", command=self.update_chain_display)
        refresh_btn.pack(pady=5)
        # Also show pending transactions
        ttk.Label(frame, text="Unconfirmed transactions").pack(pady=5)
        self.pending_text = scrolledtext.ScrolledText(frame, width=100, height=8, state='disabled')
        self.pending_text.pack(padx=10, pady=5, fill='both', expand=True)

    def create_balance_tab(self, frame):
        """Build the balance query interface."""
        ttk.Label(frame, text="Query an address balance").pack(pady=5)
        self.query_entry = ttk.Entry(frame, width=80)
        self.query_entry.pack(padx=10, pady=3, fill='x')
        query_btn = ttk.Button(frame, text="Check Balance", command=self.check_balance)
        query_btn.pack(pady=5)
        self.balance_output = scrolledtext.ScrolledText(frame, width=80, height=10, state='disabled')
        self.balance_output.pack(padx=10, pady=5, fill='both', expand=True)

    def generate_wallet(self):
        """Generate a new wallet and display the private key and address."""
        try:
            priv_key, pub_key = generate_keys()
            address = address_from_public(pub_key)
            # Serialize the private key in PEM format without encryption
            priv_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
            # Display results
            output = f"Generated new wallet:\n\nAddress: {address}\n\nPrivate Key (PEM):\n{priv_pem}\n"
            self.wallet_output.configure(state='normal')
            self.wallet_output.insert(tk.END, output + "\n")
            self.wallet_output.configure(state='disabled')
            # Automatically populate the miner address field
            self.miner_address_entry.delete(0, tk.END)
            self.miner_address_entry.insert(0, address)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate wallet: {e}")

    def submit_transaction(self):
        """Create and submit a new signed transaction from the user input."""
        priv_pem_text = self.sender_priv_key_text.get("1.0", tk.END).strip()
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()
        if not priv_pem_text or not recipient or not amount_text:
            messagebox.showwarning("Missing data", "Please provide all fields: private key, recipient and amount.")
            return
        # Parse amount
        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid amount", "Amount must be a positive number.")
            return
        # Load the private key from PEM
        try:
            private_key = serialization.load_pem_private_key(priv_pem_text.encode(), password=None)
        except Exception as e:
            messagebox.showerror("Invalid key", f"Could not load private key: {e}")
            return
        # Create and sign the transaction
        try:
            tx = Transaction(sender="", recipient=recipient, amount=amount)
            tx.sign_transaction(private_key)
        except Exception as e:
            messagebox.showerror("Signing failed", f"Could not sign transaction: {e}")
            return
        # Add the transaction to the blockchain
        try:
            self.blockchain.add_new_transaction(tx)
        except Exception as e:
            messagebox.showerror("Transaction error", str(e))
            return
        # Display result and clear fields
        self.tx_output.configure(state='normal')
        self.tx_output.insert(tk.END, f"Transaction submitted:\n  From: {tx.sender}\n  To: {tx.recipient}\n  Amount: {tx.amount}\n\n")
        self.tx_output.configure(state='disabled')
        self.sender_priv_key_text.delete("1.0", tk.END)
        self.recipient_entry.delete(0, tk.END)
        self.amount_entry.delete(0, tk.END)
        # Refresh displays
        self.update_chain_display()

    def mine_block(self):
        """Mine the pending transactions into a new block on a background thread."""
        miner_addr = self.miner_address_entry.get().strip()
        if not miner_addr:
            messagebox.showwarning("Miner address missing", "Please enter your miner address (generate a wallet first).")
            return
        # Run mining in a thread to keep UI responsive
        def mine_thread():
            self.mining_output.configure(state='normal')
            self.mining_output.insert(tk.END, "Mining started... this may take a moment.\n")
            self.mining_output.configure(state='disabled')
            new_block = self.blockchain.mine(miner_addr)
            self.mining_output.configure(state='normal')
            if new_block:
                self.mining_output.insert(
                    tk.END,
                    f"New block mined!\n  Index: {new_block.index}\n  Hash: {new_block.hash}\n  Nonce: {new_block.nonce}\n  Transactions: {len(new_block.transactions)}\n\n",
                )
            else:
                self.mining_output.insert(tk.END, "No pending transactions to mine.\n")
            self.mining_output.configure(state='disabled')
            # Refresh displays
            self.update_chain_display()

        threading.Thread(target=mine_thread, daemon=True).start()

    def update_chain_display(self):
        """Refresh the chain and pending transaction displays."""
        # Chain information
        self.chain_text.configure(state='normal')
        self.chain_text.delete("1.0", tk.END)
        for block in self.blockchain.chain:
            self.chain_text.insert(
                tk.END,
                f"Block {block.index}:\n  Timestamp: {time.ctime(block.timestamp)}\n  Previous Hash: {block.previous_hash}\n  Hash: {block.hash}\n  Nonce: {block.nonce}\n  Transactions:\n",
            )
            for tx in block.transactions:
                # Show only first 8 chars of addresses for brevity in the chain view
                sender_display = tx.sender if tx.sender == "MINING" else tx.sender[:8]
                recipient_display = tx.recipient[:8]
                self.chain_text.insert(
                    tk.END,
                    f"    {sender_display} → {recipient_display}: {tx.amount}\n",
                )
            self.chain_text.insert(tk.END, "\n")
        self.chain_text.configure(state='disabled')
        # Pending transactions
        self.pending_text.configure(state='normal')
        self.pending_text.delete("1.0", tk.END)
        for tx in self.blockchain.unconfirmed_transactions:
            sender_display = tx.sender[:8]
            recipient_display = tx.recipient[:8]
            self.pending_text.insert(
                tk.END,
                f"{sender_display} → {recipient_display}: {tx.amount}\n",
            )
        if not self.blockchain.unconfirmed_transactions:
            self.pending_text.insert(tk.END, "(none)\n")
        self.pending_text.configure(state='disabled')

    def check_balance(self):
        """Compute and display the balance for the provided address."""
        addr = self.query_entry.get().strip()
        if not addr:
            messagebox.showwarning("Address missing", "Please enter an address to query.")
            return
        balance = self.blockchain.get_balance(addr)
        self.balance_output.configure(state='normal')
        self.balance_output.insert(tk.END, f"Balance for {addr}: {balance}\n")
        self.balance_output.configure(state='disabled')


def main():
    root = tk.Tk()
    app = BlockchainGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
