"""
Main entry point for the Brixa CLI.
"""
import argparse
import asyncio
import json
import os
import sys
from typing import Optional, List, Dict, Any

from ..core.blockchain import Blockchain
from ..wallet.wallet import Wallet, create_wallet
from ..network import get_p2p_node, P2PNode

class BrixaCLI:
    """Command-line interface for interacting with the Brixa blockchain."""
    
    def __init__(self):
        self.parser = self.setup_parser()
        self.blockchain = Blockchain()
        self.current_wallet: Optional[Wallet] = None
        self.p2p_node: Optional[P2PNode] = None
        
    def setup_parser(self) -> argparse.ArgumentParser:
        """Set up the command-line argument parser."""
        parser = argparse.ArgumentParser(description='Brixa Blockchain CLI')
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Network commands
        network_parser = subparsers.add_parser('network', help='Network operations')
        network_subparsers = network_parser.add_subparsers(dest='network_command', help='Network command')
        
        # Start network node
        start_parser = network_subparsers.add_parser('start', help='Start P2P network node')
        start_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
        start_parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
        start_parser.add_argument('--peers', nargs='*', default=[], help='Initial peers to connect to (host:port)')
        
        # List peers
        peers_parser = network_subparsers.add_parser('peers', help='List connected peers')
        
        # Wallet commands
        wallet_parser = subparsers.add_parser('wallet', help='Wallet operations')
        wallet_subparsers = wallet_parser.add_subparsers(dest='wallet_command', help='Wallet command')
        
        # Create wallet
        create_parser = wallet_subparsers.add_parser('create', help='Create a new wallet')
        
        # Load wallet
        load_parser = wallet_subparsers.add_parser('load', help='Load an existing wallet')
        load_parser.add_argument('address', help='Wallet address')
        
        # Show wallet info
        info_parser = wallet_subparsers.add_parser('info', help='Show wallet information')
        
        # Blockchain commands
        chain_parser = subparsers.add_parser('chain', help='Blockchain operations')
        chain_subparsers = chain_parser.add_subparsers(dest='chain_command', help='Blockchain command')
        
        # Show blockchain info
        chain_info_parser = chain_subparsers.add_parser('info', help='Show blockchain information')
        
        # Mine block
        mine_parser = chain_subparsers.add_parser('mine', help='Mine a new block')
        
        # Show block
        block_parser = chain_subparsers.add_parser('block', help='Show block information')
        block_parser.add_argument('index', type=int, help='Block index')
        
        # Transaction commands
        tx_parser = subparsers.add_parser('tx', help='Transaction operations')
        tx_subparsers = tx_parser.add_subparsers(dest='tx_command', help='Transaction command')
        
        # Create transaction
        create_tx_parser = tx_subparsers.add_parser('create', help='Create a new transaction')
        create_tx_parser.add_argument('recipient', help='Recipient address')
        create_tx_parser.add_argument('amount', type=float, help='Amount to send')
        
        # Show transaction
        show_tx_parser = tx_subparsers.add_parser('show', help='Show transaction')
        show_tx_parser.add_argument('txid', help='Transaction ID')
        
        return parser
    
    async def run(self):
        """Run the CLI."""
        args = self.parser.parse_args()
        
        if not hasattr(args, 'command'):
            self.parser.print_help()
            return
            
        # Handle network commands
        if args.command == 'network':
            if args.network_command == 'start':
                await self.start_network(args.host, args.port, args.peers)
            elif args.network_command == 'peers':
                await self.list_peers()
            return
            
        if args.command == 'wallet':
            await self.handle_wallet_command(args)
        elif args.command == 'chain':
            await self.handle_chain_command(args)
        elif args.command == 'tx':
            await self.handle_tx_command(args)
    
    async def handle_wallet_command(self, args):
        """Handle wallet commands."""
        if args.wallet_command == 'create':
            await self.create_wallet()
        elif args.wallet_command == 'load':
            await self.load_wallet(args.address)
        elif args.wallet_command == 'info':
            await self.show_wallet_info()
    
    async def handle_chain_command(self, args):
        """Handle blockchain commands."""
        if args.chain_command == 'info':
            await self.show_chain_info()
        elif args.chain_command == 'mine':
            await self.mine_block()
        elif args.chain_command == 'block':
            await self.show_block(args.index)
    
    async def handle_tx_command(self, args):
        """Handle transaction commands."""
        if args.tx_command == 'create':
            await self.create_transaction(args.recipient, args.amount)
        elif args.tx_command == 'show':
            await self.show_transaction(args.txid)
    
    async def create_wallet(self):
        """Create a new wallet."""
        wallet = create_wallet()
        print(f"Created new wallet:")
        print(f"Address: {wallet.address}")
        print(f"Private key: {wallet.private_key.hex()}")
        print("\nIMPORTANT: Save your private key in a secure location!")
    
    async def load_wallet(self, address: str):
        """Load an existing wallet."""
        try:
            # Try with .json extension first
            wallet_file = f"wallets/{address}.json"
            if not os.path.exists(wallet_file):
                # If not found, try without .json extension
                wallet_file = f"wallets/{address}"
                if not os.path.exists(wallet_file):
                    print(f"Error: Wallet {address} not found")
                    return None
                    
            self.current_wallet = Wallet.load_from_file(wallet_file)
            print(f"Loaded wallet: {self.current_wallet.address}")
            return self.current_wallet
        except Exception as e:
            print(f"Error loading wallet: {str(e)}")
            return None
    
    async def show_wallet_info(self):
        """Show wallet information."""
        if not self.current_wallet:
            print("Error: No wallet loaded. Use 'wallet load <address>' to load a wallet.")
            return
            
        balance = self.blockchain.get_balance(self.current_wallet.address)
        print(f"Address: {self.current_wallet.address}")
        print(f"Balance: {balance / 1e8:.8f} BXA")
    
    async def show_chain_info(self):
        """Show blockchain information."""
        chain_length = len(self.blockchain.chain)
        difficulty = self.blockchain.difficulty
        pending_txs = len(self.blockchain.pending_transactions)
        print(f"Blockchain Information:")
        print(f"Blocks: {chain_length}")
        print(f"Difficulty: {difficulty}")
        print(f"Pending transactions: {pending_txs}")
    
    async def start_network(self, host: str, port: int, peers: List[str]) -> None:
        """Start the P2P network node."""
        print(f"Starting P2P node on {host}:{port}")
        self.p2p_node = await get_p2p_node(host=host, port=port)
        
        # Parse peer addresses
        initial_peers = []
        for peer_str in peers:
            if ':' in peer_str:
                host, port_str = peer_str.split(':', 1)
                try:
                    initial_peers.append((host, int(port_str)))
                except ValueError:
                    print(f"Invalid port for peer {peer_str}")
        
        # Connect to initial peers
        if initial_peers:
            print(f"Connecting to {len(initial_peers)} initial peers...")
            await self.p2p_node.connect_to_peers(initial_peers)
        
        print("P2P node started. Press Ctrl+C to stop.")
        try:
            # Keep the node running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping P2P node...")
            await self.p2p_node.stop()
    
    async def list_peers(self) -> None:
        """List connected peers."""
        if not self.p2p_node:
            print("Error: Network node not started. Use 'network start' first.")
            return
            
        print("\nConnected peers:")
        for i, peer in enumerate(self.p2p_node.peers, 1):
            print(f"{i}. {peer.host}:{peer.port}")
        
        if not self.p2p_node.peers:
            print("No peers connected.")
    
    async def mine_block(self):
        """Mine a new block."""
        if not self.current_wallet:
            print("Error: No wallet loaded. Use 'wallet load <address>' to load a wallet.")
            return
            
        print("Mining new block...")
        block = await self.blockchain.mine_pending_transactions(self.current_wallet.address)
        
        if block:
            print(f"Mined block {block.index} with hash: {block.hash}")
            # Broadcast the new block to the network
            if self.p2p_node:
                block_data = block.to_dict()
                await self.p2p_node.broadcast_block(block_data)
        else:
            print("No transactions to mine.")
    
    async def show_block(self, index: int):
        """Show block information."""
        try:
            block = self.blockchain.chain[index]
            print(f"Block {block.index}:")
            print(f"Hash: {block.hash}")
            print(f"Previous hash: {block.previous_hash}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Transactions: {len(block.transactions)}")
            print(f"Nonce: {block.nonce}")
            print(f"Proof: {block.proof.hex() if block.proof else 'None'}")
        except IndexError:
            print(f"Error: Block {index} not found")
    
    async def create_transaction(self, recipient: str, amount: float):
        """Create a new transaction."""
        if not self.current_wallet:
            print("Error: No wallet loaded. Use 'wallet load <address>' to load a wallet.")
            return
            
        # Convert amount to satoshis
        satoshis = int(amount * 1e8)
        
        # Create transaction
        tx = {
            'version': 1,
            'inputs': [
                # In a real implementation, you would select UTXOs here
                {
                    'txid': '0' * 64,  # Placeholder
                    'vout': 0,          # Placeholder
                    'script_sig': '',    # Will be signed
                    'sequence': 0xffffffff
                }
            ],
            'outputs': [
                {
                    'value': satoshis,
                    'script_pubkey': f"OP_DUP OP_HASH160 {recipient} OP_EQUALVERIFY OP_CHECKSIG",
                    'address': recipient
                }
            ],
            'locktime': 0
        }
        
        # Sign the transaction
        signature = self.current_wallet.sign(tx)
        tx['inputs'][0]['script_sig'] = f"{signature} {self.current_wallet.public_key.hex()}"
        
        # Add to pending transactions
        self.blockchain.pending_transactions.append(tx)
        
        print(f"Created transaction. {len(self.blockchain.pending_transactions)} pending transactions.")
    
    async def show_transaction(self, txid: str):
        """Show transaction information."""
        # Search for transaction in blockchain
        for block in self.blockchain.chain:
            for tx in block.transactions:
                if tx.get('txid') == txid:
                    print(f"Transaction {txid}:")
                    print(f"Block: {block.index}")
                    print(f"Inputs: {len(tx.get('inputs', []))}")
                    print(f"Outputs: {len(tx.get('outputs', []))}")
                    return
        
        # Check pending transactions
        for tx in self.blockchain.pending_transactions:
            if tx.get('txid') == txid:
                print(f"Pending transaction {txid}:")
                print(f"Inputs: {len(tx.get('inputs', []))}")
                print(f"Outputs: {len(tx.get('outputs', []))}")
                return
        
        print(f"Transaction {txid} not found")

def main():
    """Main entry point for the CLI."""
    cli = BrixaCLI()
    asyncio.run(cli.run())

if __name__ == '__main__':
    main()
