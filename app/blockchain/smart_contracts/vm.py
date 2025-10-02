""
Virtual Machine for Brixa Smart Contracts

Implements a secure, sandboxed environment for executing smart contracts.
"""
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Type, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VMError(Exception):
    """Base exception for VM-related errors."""
    pass

class OpCode(Enum):
    """Bytecode operation codes."""
    NOP = 0x00
    PUSH = 0x01
    POP = 0x02
    DUP = 0x03
    SWAP = 0x04
    ADD = 0x10
    SUB = 0x11
    MUL = 0x12
    DIV = 0x13
    MOD = 0x14
    EXP = 0x15
    LT = 0x20
    GT = 0x21
    EQ = 0x22
    AND = 0x30
    OR = 0x31
    NOT = 0x32
    XOR = 0x33
    SHA3 = 0x40
    CALL = 0x50
    CALLCODE = 0x51
    DELEGATECALL = 0x52
    RETURN = 0x60
    REVERT = 0x61
    STOP = 0x62
    JUMP = 0x70
    JUMPI = 0x71
    PC = 0x72
    MSIZE = 0x73
    GAS = 0x74
    JUMPDEST = 0x75
    ORIGIN = 0x80
    CALLER = 0x81
    CALLVALUE = 0x82
    BALANCE = 0x83
    BLOCKHASH = 0x84
    COINBASE = 0x85
    TIMESTAMP = 0x86
    NUMBER = 0x87
    DIFFICULTY = 0x88
    GASLIMIT = 0x89
    SLOAD = 0x90
    SSTORE = 0x91
    MSTORE = 0x92
    MLOAD = 0x93
    MSTORE8 = 0x94
    CREATE = 0x95
    CALLDATALOAD = 0x96
    CALLDATACOPY = 0x97
    CODECOPY = 0x98
    EXTCODESIZE = 0x99
    EXTCODECOPY = 0x9A
    SELFDESTRUCT = 0xFF

@dataclass
class Stack:
    """LIFO stack for the VM."""
    items: List[bytes] = field(default_factory=list)
    max_size: int = 1024

    def push(self, item: bytes) -> None:
        if len(self.items) >= self.max_size:
            raise VMError("Stack overflow")
        self.items.append(item)

    def pop(self) -> bytes:
        if not self.items:
            raise VMError("Stack underflow")
        return self.items.pop()

    def peek(self) -> bytes:
        if not self.items:
            raise VMError("Stack underflow")
        return self.items[-1]

    def __len__(self) -> int:
        return len(self.items)

@dataclass
class Memory:
    """Expandable byte array for the VM."""
    data: bytearray = field(default_factory=bytearray)
    
    def store(self, offset: int, value: bytes) -> None:
        """Store bytes at the given offset."""
        end = offset + len(value)
        if end > len(self.data):
            # Expand memory if needed
            self.data.extend(bytearray(end - len(self.data)))
        self.data[offset:end] = value
    
    def load(self, offset: int, size: int) -> bytes:
        """Load bytes from the given offset."""
        end = offset + size
        if end > len(self.data):
            # Return zero-padded bytes if reading beyond memory
            return bytes(size)
        return bytes(self.data[offset:end])

@dataclass
class Storage:
    """Key-value storage for contracts."""
    data: Dict[bytes, bytes] = field(default_factory=dict)
    
    def store(self, key: bytes, value: bytes) -> None:
        """Store a value at the given key."""
        if not value:
            self.data.pop(key, None)
        else:
            self.data[key] = value
    
    def load(self, key: bytes) -> bytes:
        """Load a value from the given key."""
        return self.data.get(key, b'')

@dataclass
class ExecutionContext:
    """Context for contract execution."""
    code: bytes
    stack: Stack = field(default_factory=Stack)
    memory: Memory = field(default_factory=Memory)
    storage: Storage = field(default_factory=Storage)
    pc: int = 0  # Program counter
    gas: int = 0
    gas_used: int = 0
    return_data: bytes = b''
    
    def consume_gas(self, amount: int) -> None:
        """Consume gas, raising an exception if not enough gas is available."""
        if self.gas < amount:
            raise VMError("Out of gas")
        self.gas -= amount
        self.gas_used += amount

class VirtualMachine:
    """
    Brixa Virtual Machine for executing smart contracts.
    
    Implements a secure, sandboxed environment for executing smart contracts
    with a custom bytecode instruction set.
    """
    
    def __init__(self, gas_limit: int = 10_000_000):
        self.gas_limit = gas_limit
        self.contracts: Dict[bytes, bytes] = {}
        self.logs: List[Dict[str, Any]] = []
    
    def execute(self, code: bytes, context: Optional[ExecutionContext] = None) -> bytes:
        """
        Execute the given bytecode in a new execution context.
        
        Args:
            code: The bytecode to execute
            context: Optional execution context (creates a new one if not provided)
            
        Returns:
            The return data from the execution
        """
        if context is None:
            context = ExecutionContext(
                code=code,
                gas=self.gas_limit
            )
        
        try:
            while context.pc < len(context.code):
                opcode = context.code[context.pc]
                self._execute_opcode(opcode, context)
                context.pc += 1
                
                # Check gas limit
                if context.gas_used >= self.gas_limit:
                    raise VMError("Gas limit exceeded")
                    
        except VMError as e:
            logger.error(f"VM execution error: {e}")
            context.return_data = b''  # Clear return data on error
            raise
            
        return context.return_data
    
    def _execute_opcode(self, opcode: int, context: ExecutionContext) -> None:
        """Execute a single opcode."""
        try:
            op = OpCode(opcode)
        except ValueError:
            raise VMError(f"Invalid opcode: 0x{opcode:02x}")
        
        # Execute the operation
        if op == OpCode.STOP:
            context.pc = len(context.code)  # Stop execution
        elif op == OpCode.ADD:
            a = int.from_bytes(context.stack.pop(), 'big')
            b = int.from_bytes(context.stack.pop(), 'big')
            result = (a + b) & ((1 << 256) - 1)  # 256-bit arithmetic
            context.stack.push(result.to_bytes(32, 'big'))
        # TODO: Implement remaining opcodes
        else:
            raise VMError(f"Unimplemented opcode: {op.name}")
    
    def create_contract(self, code: bytes, sender: bytes, value: int = 0) -> bytes:
        """
        Create a new contract with the given code.
        
        Args:
            code: The contract bytecode
            sender: The address of the account creating the contract
            value: The amount of BXA to send to the contract
            
        Returns:
            The address of the newly created contract
        """
        # Generate contract address (sender + nonce would be used in a real implementation)
        contract_hash = hashlib.sha256(sender + code).digest()
        contract_address = contract_hash[:20]  # First 20 bytes as address
        
        # Store the contract code
        self.contracts[contract_address] = code
        
        # Initialize the contract
        context = ExecutionContext(
            code=code,
            gas=self.gas_limit
        )
        
        try:
            self.execute(code, context)
        except VMError as e:
            logger.error(f"Contract creation failed: {e}")
            return b''
            
        return contract_address
    
    def call_contract(self, 
                     address: bytes, 
                     data: bytes = b'', 
                     sender: bytes = None, 
                     value: int = 0) -> bytes:
        """
        Call a contract with the given data.
        
        Args:
            address: The contract address to call
            data: The call data (function selector + arguments)
            sender: The address of the caller
            value: The amount of BXA to send with the call
            
        Returns:
            The return data from the contract call
        """
        if address not in self.contracts:
            raise VMError(f"No contract at address {address.hex()}")
            
        code = self.contracts[address]
        context = ExecutionContext(
            code=code,
            gas=self.gas_limit
        )
        
        # Set up call data in memory
        if data:
            context.memory.store(0, data)
        
        # Execute the contract
        try:
            return self.execute(code, context)
        except VMError as e:
            logger.error(f"Contract call failed: {e}")
            return b''

# Example usage
if __name__ == "__main__":
    # Simple contract that adds two numbers and returns the result
    # PUSH1 0x02  (push 2 onto the stack)
    # PUSH1 0x03  (push 3 onto the stack)
    # ADD        (add them)
    # PUSH1 0x00  (memory location 0)
    # MSTORE     (store result in memory)
    # PUSH1 0x20  (32 bytes)
    # PUSH1 0x00  (memory location 0)
    # RETURN     (return the 32-byte result)
    bytecode = bytes([
        0x60, 0x02,  # PUSH1 0x02
        0x60, 0x03,  # PUSH1 0x03
        0x01,        # ADD
        0x60, 0x00,  # PUSH1 0x00
        0x52,        # MSTORE
        0x60, 0x20,  # PUSH1 0x20
        0x60, 0x00,  # PUSH1 0x00
        0xF3         # RETURN
    ])
    
    vm = VirtualMachine()
    result = vm.execute(bytecode)
    print(f"Result: {int.from_bytes(result, 'big')}")  # Should print: Result: 5
