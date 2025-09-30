"""
Transaction model and related functionality for the Brixa blockchain.
Implements a Bitcoin-like transaction structure with BXA tokens.
"""
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime

# Constants
MAX_MONEY = 21_000_000 * 100_000_000  # 21 million BXA in satoshis
DEFAULT_SEQUENCE = 0xffffffff
LOCKTIME_THRESHOLD = 500000000  # Timestamp threshold for locktime
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

@dataclass
class TransactionInput:
    """
    Represents a transaction input (unspent transaction output reference).
    Follows Bitcoin's transaction input structure.
    """
    txid: str  # Reference to the transaction containing the output being spent (32 bytes, little-endian)
    vout: int  # Index of the output in the referenced transaction (uint32)
    script_sig: str  # Script that satisfies the conditions of the output being spent (varint + bytes)
    sequence: int = DEFAULT_SEQUENCE  # Sequence number (uint32, used for locktime)
    witness: List[str] = field(default_factory=list)  # Witness data for SegWit
    
    def __post_init__(self):
        """Validate the input after initialization."""
        if not isinstance(self.txid, str) or len(bytes.fromhex(self.txid)) != 32:
            raise ValueError("txid must be a 32-byte hex string")
        if not (0 <= self.vout <= 0xffffffff):
            raise ValueError("vout must be a 32-bit unsigned integer")
        if not (0 <= self.sequence <= 0xffffffff):
            raise ValueError("sequence must be a 32-bit unsigned integer")
    
    def serialize(self) -> bytes:
        """Serialize the input to bytes."""
        # txid (32 bytes, little-endian)
        txid = bytes.fromhex(self.txid)[::-1]
        
        # vout (4 bytes, little-endian)
        vout = struct.pack('<I', self.vout)
        
        # script_sig (varint + bytes)
        script_sig = bytes.fromhex(self.script_sig)
        script_len = self._varint(len(script_sig))
        
        # sequence (4 bytes, little-endian)
        sequence = struct.pack('<I', self.sequence)
        
        return txid + vout + script_len + script_sig + sequence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the input to a dictionary."""
        return {
            'txid': self.txid,
            'vout': self.vout,
            'script_sig': self.script_sig,
            'sequence': self.sequence,
            'witness': self.witness
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionInput':
        """Create an input from a dictionary."""
        return cls(
            txid=data['txid'],
            vout=data['vout'],
            script_sig=data['script_sig'],
            sequence=data.get('sequence', DEFAULT_SEQUENCE),
            witness=data.get('witness', [])
        )
    
    def _varint(self, n: int) -> bytes:
        """Convert a number to a variable-length integer."""
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n <= 0xffff:
            return struct.pack('<BH', 0xfd, n)
        elif n <= 0xffffffff:
            return struct.pack('<BI', 0xfe, n)
        else:
            return struct.pack('<BQ', 0xff, n)

@dataclass
class TransactionOutput:
    """
    Represents a transaction output.
    Follows Bitcoin's transaction output structure.
    """
    value: int  # Amount in satoshis (smallest unit of BXA, int64)
    script_pubkey: str  # Script that defines the conditions to spend this output (varint + bytes)
    address: str = ''  # Human-readable address (not part of the serialized output)
    
    def __post_init__(self):
        """Validate the output after initialization."""
        if not (0 <= self.value <= MAX_MONEY):
            raise ValueError(f"Invalid output value: {self.value} (max: {MAX_MONEY})")
        if not isinstance(self.script_pubkey, str) or not all(c in '0123456789abcdef' for c in self.script_pubkey):
            raise ValueError("script_pubkey must be a hex string")
    
    def serialize(self) -> bytes:
        """Serialize the output to bytes."""
        # value (8 bytes, little-endian)
        value = struct.pack('<q', self.value)
        
        # script_pubkey (varint + bytes)
        script = bytes.fromhex(self.script_pubkey)
        script_len = self._varint(len(script))
        
        return value + script_len + script
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the output to a dictionary."""
        return {
            'value': self.value,
            'script_pubkey': self.script_pubkey,
            'address': self.address
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionOutput':
        """Create an output from a dictionary."""
        return cls(
            value=data['value'],
            script_pubkey=data['script_pubkey'],
            address=data.get('address', '')
        )
    
    def _varint(self, n: int) -> bytes:
        """Convert a number to a variable-length integer."""
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n <= 0xffff:
            return struct.pack('<BH', 0xfd, n)
        elif n <= 0xffffffff:
            return struct.pack('<BI', 0xfe, n)
        else:
            return struct.pack('<BQ', 0xff, n)

@dataclass
class Transaction:
    """
    Represents a Brixa blockchain transaction.
    Follows Bitcoin's transaction structure with BXA tokens.
    """
    version: int = 1  # Transaction version (signed 32-bit integer)
    inputs: List[TransactionInput] = field(default_factory=list)
    outputs: List[TransactionOutput] = field(default_factory=list)
    locktime: int = 0  # Block number or timestamp until which the transaction is locked (uint32)
    txid: str = field(init=False)  # Transaction ID (hash of the transaction)
    is_coinbase: bool = field(default=False, init=False)  # Whether this is a coinbase transaction
    
    def __post_init__(self):
        """Validate and finalize the transaction after initialization."""
        if not (-0x80000000 <= self.version <= 0x7fffffff):
            raise ValueError("Transaction version out of range")
        if not (0 <= self.locktime <= 0xffffffff):
            raise ValueError("Locktime must be a 32-bit unsigned integer")
        if not self.inputs and not self.is_coinbase:
            raise ValueError("Transaction must have at least one input")
        if not self.outputs:
            raise ValueError("Transaction must have at least one output")
            
        # Calculate the transaction ID
        self.txid = self.calculate_txid()
    
    def serialize(self, include_witness: bool = False) -> bytes:
        """
        Serialize the transaction to bytes.
        
        Args:
            include_witness: Whether to include witness data (for SegWit)
            
        Returns:
            bytes: Serialized transaction
        """
        # Version (4 bytes, little-endian)
        version = struct.pack('<i', self.version)
        
        # Marker and flag for SegWit
        marker = b'\x00' if include_witness and any(inp.witness for inp in self.inputs) else b''
        flag = b'\x01' if marker else b''
        
        # Inputs (varint + inputs)
        inputs_count = self._varint(len(self.inputs))
        inputs = b''.join(inp.serialize() for inp in self.inputs)
        
        # Outputs (varint + outputs)
        outputs_count = self._varint(len(self.outputs))
        outputs = b''.join(out.serialize() for out in self.outputs)
        
        # Witness data (if SegWit)
        witness = b''
        if marker and flag:
            witness = b''.join(
                self._serialize_witness(inp.witness) for inp in self.inputs
            )
        
        # Locktime (4 bytes, little-endian)
        locktime = struct.pack('<I', self.locktime)
        
        # Combine all parts
        return version + marker + flag + inputs_count + inputs + outputs_count + outputs + witness + locktime
    
    def calculate_txid(self) -> str:
        """
        Calculate the transaction ID (double SHA-256 hash of the serialized transaction).
        For SegWit transactions, this excludes witness data.
        """
        tx_bytes = self.serialize(include_witness=False)
        hash1 = hashlib.sha256(tx_bytes).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2[::-1].hex()  # Convert to little-endian hex
    
    def to_dict(self, include_txid: bool = True) -> Dict[str, Any]:
        """
        Convert the transaction to a dictionary.
        
        Args:
            include_txid: Whether to include the txid in the output
            
        Returns:
            dict: Dictionary representation of the transaction
        """
        result = {
            'version': self.version,
            'inputs': [input_.to_dict() for input_ in self.inputs],
            'outputs': [output.to_dict() for output in self.outputs],
            'locktime': self.locktime,
            'is_coinbase': self.is_coinbase
        }
        
        if include_txid:
            result['txid'] = self.txid
            
        return result
    
    def _varint(self, n: int) -> bytes:
        """Convert a number to a variable-length integer."""
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n <= 0xffff:
            return struct.pack('<BH', 0xfd, n)
        elif n <= 0xffffffff:
            return struct.pack('<BI', 0xfe, n)
        else:
            return struct.pack('<BQ', 0xff, n)
    
    def _serialize_witness(self, witness: List[str]) -> bytes:
        """Serialize witness data."""
        if not witness:
            return b'\x00'  # Empty witness
            
        witness_count = self._varint(len(witness))
        witness_data = b''
        
        for item in witness:
            item_bytes = bytes.fromhex(item)
            witness_data += self._varint(len(item_bytes)) + item_bytes
            
        return witness_count + witness_data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """Create a transaction from a dictionary."""
        tx = cls(
            version=data.get('version', 1),
            inputs=[TransactionInput.from_dict(i) for i in data.get('inputs', [])],
            outputs=[TransactionOutput.from_dict(o) for o in data.get('outputs', [])],
            locktime=data.get('locktime', 0)
        )
        
        # Manually set the txid if it exists in the data
        if 'txid' in data:
            object.__setattr__(tx, 'txid', data['txid'])
            
        return tx
    
    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction (first transaction in a block)."""
        return len(self.inputs) == 1 and self.inputs[0].txid == '0' * 64 and self.inputs[0].vout == 0xffffffff
    
    def verify(self) -> bool:
        """Verify the transaction is valid."""
        # Check basic structure
        if not self.inputs or not self.outputs:
            return False
            
        # Check for negative values in outputs
        if any(output.value < 0 for output in self.outputs):
            return False
            
        # Verify the transaction ID
        if self.txid != self.calculate_txid():
            return False
            
        # TODO: Add signature verification
        
        return True

def create_coinbase_transaction(address: str, value: int, height: int, extra_nonce: bytes = b'') -> Transaction:
    """
    Create a coinbase transaction (first transaction in a block).
    
    Args:
        address: The miner's address to receive the block reward
        value: The block reward amount in satoshis
        height: The block height (used in the coinbase script)
        extra_nonce: Extra nonce to include in the coinbase script
        
    Returns:
        A new coinbase transaction
    """
    # Create a special input for the coinbase transaction
    coinbase_input = TransactionInput(
        txid='0' * 64,  # All zeros for coinbase
        vout=0xffffffff,  # Max value for coinbase
        script_sig=create_coinbase_script(height, extra_nonce),
        sequence=0xffffffff
    )
    
    # Create the output to the miner's address
    coinbase_output = TransactionOutput(
        value=value,
        script_pubkey=address_to_script(address),
        address=address
    )
    
    # Create and return the transaction
    tx = Transaction(
        version=1,
        inputs=[coinbase_input],
        outputs=[coinbase_output],
        locktime=0
    )
    tx.is_coinbase = True
    return tx


def create_coinbase_script(height: int, extra_nonce: bytes = b'') -> str:
    """
    Create a coinbase script with the block height and extra nonce.
    
    Args:
        height: The block height
        extra_nonce: Extra nonce to include in the script
        
    Returns:
        str: Hex-encoded coinbase script
    """
    # Start with the block height (BIP34)
    height_bytes = bytes([len(bytearray([height]))]) + height.to_bytes((height.bit_length() + 7) // 8, 'little')
    
    # Add extra nonce if provided
    script = height_bytes + extra_nonce
    
    # Add some random bytes if needed to reach minimum size
    min_size = 2  # Minimum 2 bytes for BIP34
    if len(script) < min_size:
        script += os.urandom(min_size - len(script))
    
    return script.hex()


def address_to_script(address: str) -> str:
    """
    Convert a Brixa address to a scriptPubKey.
    
    Args:
        address: The Brixa address
        
    Returns:
        str: Hex-encoded scriptPubKey
    """
    # This is a simplified version. In a real implementation, you would:
    # 1. Decode the base58/bech32 address
    # 2. Extract the address type and hash
    # 3. Create the appropriate scriptPubKey
    
    # For now, we'll use a simple P2PKH script
    # OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    if address.startswith('B'):  # P2PKH address
        # In a real implementation, you would decode the base58 address
        # and extract the pubkey hash (20 bytes)
        pubkey_hash = '00' * 20  # Placeholder
        return f"76a914{pubkey_hash}88ac"
    else:
        raise ValueError(f"Unsupported address format: {address}")


def verify_transaction(transaction: Transaction, utxo_set: Dict[str, Dict[int, TransactionOutput]]) -> bool:
    """
    Verify a transaction is valid.
    
    Args:
        transaction: The transaction to verify
        utxo_set: The current UTXO set
        
    Returns:
        bool: True if the transaction is valid, False otherwise
    """
    # Skip coinbase transactions for now (they're validated separately)
    if transaction.is_coinbase:
        return True
    
    # Check for empty inputs
    if not transaction.inputs:
        return False
    
    # Check for empty outputs
    if not transaction.outputs:
        return False
    
    # Check for duplicate inputs
    input_set = set()
    for txin in transaction.inputs:
        input_key = f"{txin.txid}:{txin.vout}"
        if input_key in input_set:
            return False  # Duplicate input
        input_set.add(input_key)
    
    # Check each input is in the UTXO set and not already spent
    total_in = 0
    for i, txin in enumerate(transaction.inputs):
        # Check if the referenced output exists
        if txin.txid not in utxo_set or txin.vout not in utxo_set[txin.txid]:
            return False  # Referenced output not found
        
        # Get the referenced output
        prev_out = utxo_set[txin.txid][txin.vout]
        
        # Add to the total input value
        total_in += prev_out.value
    
    # Check for overflow in output values
    total_out = 0
    for txout in transaction.outputs:
        if txout.value < 0 or txout.value > MAX_MONEY:
            return False  # Invalid output value
        total_out += txout.value
        
        # Check for overflow
        if total_out < 0 or total_out > MAX_MONEY:
            return False
    
    # Check that the outputs don't exceed the inputs (except for coinbase)
    if total_in < total_out:
        return False  # Not enough input value
    
    # TODO: Verify signatures (this is complex and requires script evaluation)
    
    return True
