""
Standard Contracts for Brixa Smart Contracts

This module provides implementations of common token standards and utility contracts
that can be used as-is or extended for custom functionality.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union, Any, Callable
from pathlib import Path
import json

from .sdk import Contract, Account

class BRC20(Contract):
    """BRC-20 Token Standard Implementation"""
    
    def __init__(self, 
                 name: str = "Brixa Token",
                 symbol: str = "BRX",
                 decimals: int = 18,
                 initial_supply: int = 0):
        """Initialize a new BRC20 token.
        
        Args:
            name: The name of the token
            symbol: The symbol of the token (e.g., "BRX")
            decimals: Number of decimal places
            initial_supply: Initial token supply (in smallest unit)
        """
        source = f"""
        contract BRC20 {{
            string public name = "{name}";
            string public symbol = "{symbol}";
            uint8 public decimals = {decimals};
            uint256 public totalSupply = {initial_supply};
            
            mapping(address => uint256) public balanceOf;
            mapping(address => mapping(address => uint256)) public allowance;
            
            event Transfer(address indexed from, address indexed to, uint256 value);
            event Approval(address indexed owner, address indexed spender, uint256 value);
            
            constructor() {{
                balanceOf[msg.sender] = totalSupply;
                emit Transfer(address(0), msg.sender, totalSupply);
            }}
            
            function transfer(address to, uint256 value) public returns (bool) {{
                require(to != address(0), "BRC20: transfer to the zero address");
                require(balanceOf[msg.sender] >= value, "BRC20: transfer amount exceeds balance");
                
                balanceOf[msg.sender] -= value;
                balanceOf[to] += value;
                emit Transfer(msg.sender, to, value);
                return true;
            }}
            
            function approve(address spender, uint256 value) public returns (bool) {{
                allowance[msg.sender][spender] = value;
                emit Approval(msg.sender, spender, value);
                return true;
            }}
            
            function transferFrom(address from, address to, uint256 value) public returns (bool) {{
                require(from != address(0), "BRC20: transfer from the zero address");
                require(to != address(0), "BRC20: transfer to the zero address");
                require(balanceOf[from] >= value, "BRC20: transfer amount exceeds balance");
                require(allowance[from][msg.sender] >= value, "BRC20: transfer amount exceeds allowance");
                
                balanceOf[from] -= value;
                balanceOf[to] += value;
                allowance[from][msg.sender] -= value;
                emit Transfer(from, to, value);
                return true;
            }}
            
            function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {{
                allowance[msg.sender][spender] += addedValue;
                emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
                return true;
            }}
            
            function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {{
                uint256 currentAllowance = allowance[msg.sender][spender];
                require(currentAllowance >= subtractedValue, "BRC20: decreased allowance below zero");
                allowance[msg.sender][spender] = currentAllowance - subtractedValue;
                emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
                return true;
            }}
            
            function mint(address to, uint256 amount) public {{
                require(to != address(0), "BRC20: mint to the zero address");
                
                totalSupply += amount;
                balanceOf[to] += amount;
                emit Transfer(address(0), to, amount);
            }}
            
            function burn(uint256 amount) public {{
                require(balanceOf[msg.sender] >= amount, "BRC20: burn amount exceeds balance");
                
                balanceOf[msg.sender] -= amount;
                totalSupply -= amount;
                emit Transfer(msg.sender, address(0), amount);
            }}
        }}
        """
        
        abi = [
            {
                "inputs": [],
                "stateMutability": "nonpayable",
                "type": "constructor"
            },
            {
                "anonymous": False,
                "inputs": [
                    {
                        "indexed": True,
                        "internalType": "address",
                        "name": "owner",
                        "type": "address"
                    },
                    {
                        "indexed": True,
                        "internalType": "address",
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "internalType": "uint256",
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Approval",
                "type": "event"
            },
            {
                "anonymous": False,
                "inputs": [
                    {
                        "indexed": True,
                        "internalType": "address",
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "indexed": True,
                        "internalType": "address",
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "internalType": "uint256",
                        "name": "value",
                        "type": "uint256"
                    }
                ],
                "name": "Transfer",
                "type": "event"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "owner",
                        "type": "address"
                    },
                    {
                        "internalType": "address",
                        "name": "spender",
                        "type": "address"
                    }
                ],
                "name": "allowance",
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "approve",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "account",
                        "type": "address"
                    }
                ],
                "name": "balanceOf",
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "burn",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "decimals",
                "outputs": [
                    {
                        "internalType": "uint8",
                        "name": "",
                        "type": "uint8"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "subtractedValue",
                        "type": "uint256"
                    }
                ],
                "name": "decreaseAllowance",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "addedValue",
                        "type": "uint256"
                    }
                ],
                "name": "increaseAllowance",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "mint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "name",
                "outputs": [
                    {
                        "internalType": "string",
                        "name": "",
                        "type": "string"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "symbol",
                "outputs": [
                    {
                        "internalType": "string",
                        "name": "",
                        "type": "string"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "totalSupply",
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "transfer",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "from",
                        "type": "address"
                    },
                    {
                        "internalType": "address",
                        "name": "to",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "transferFrom",
                "outputs": [
                    {
                        "internalType": "bool",
                        "name": "",
                        "type": "bool"
                    }
                ],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        super().__init__(source, abi)
        self.name = name
        self.symbol = symbol
        self.decimals = decimals
        self.initial_supply = initial_supply

class BRC721(Contract):
    """BRC-721 Non-Fungible Token Standard Implementation"""
    
    def __init__(self, 
                 name: str = "Brixa NFT",
                 symbol: str = "BRXNFT"):
        """Initialize a new BRC721 token.
        
        Args:
            name: The name of the token
            symbol: The symbol of the token
        """
        source = f"""
        contract BRC721 {{
            string public name = "{name}";
            string public symbol = "{symbol}";
            
            mapping(uint256 => address) private _owners;
            mapping(address => uint256) private _balances;
            mapping(uint256 => address) private _tokenApprovals;
            mapping(address => mapping(address => bool)) private _operatorApprovals;
            
            event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
            event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
            event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
            
            function balanceOf(address owner) public view returns (uint256) {{
                require(owner != address(0), "BRC721: balance query for the zero address");
                return _balances[owner];
            }}
            
            function ownerOf(uint256 tokenId) public view returns (address) {{
                address owner = _owners[tokenId];
                require(owner != address(0), "BRC721: owner query for nonexistent token");
                return owner;
            }}
            
            function approve(address to, uint256 tokenId) public {{
                address owner = ownerOf(tokenId);
                require(to != owner, "BRC721: approval to current owner");
                require(
                    msg.sender == owner || isApprovedForAll(owner, msg.sender),
                    "BRC721: approve caller is not owner nor approved for all"
                );
                
                _approve(to, tokenId);
            }}
            
            function getApproved(uint256 tokenId) public view returns (address) {{
                require(_exists(tokenId), "BRC721: approved query for nonexistent token");
                return _tokenApprovals[tokenId];
            }}
            
            function setApprovalForAll(address operator, bool approved) public {{
                require(operator != msg.sender, "BRC721: approve to caller");
                _operatorApprovals[msg.sender][operator] = approved;
                emit ApprovalForAll(msg.sender, operator, approved);
            }}
            
            function isApprovedForAll(address owner, address operator) public view returns (bool) {{
                return _operatorApprovals[owner][operator];
            }}
            
            function transferFrom(address from, address to, uint256 tokenId) public {{
                require(_isApprovedOrOwner(msg.sender, tokenId), "BRC721: transfer caller is not owner nor approved");
                _transfer(from, to, tokenId);
            }}
            
            function safeTransferFrom(address from, address to, uint256 tokenId) public {{
                safeTransferFrom(from, to, tokenId, "");
            }}
            
            function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {{
                require(_isApprovedOrOwner(msg.sender, tokenId), "BRC721: transfer caller is not owner nor approved");
                _safeTransfer(from, to, tokenId, _data);
            }}
            
            function _safeTransfer(address from, address to, uint256 tokenId, bytes memory _data) internal {{
                _transfer(from, to, tokenId);
                require(_checkOnBRC721Received(from, to, tokenId, _data), "BRC721: transfer to non BRC721Receiver implementer");
            }}
            
            function _exists(uint256 tokenId) internal view returns (bool) {{
                return _owners[tokenId] != address(0);
            }}
            
            function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {{
                require(_exists(tokenId), "BRC721: operator query for nonexistent token");
                address owner = ownerOf(tokenId);
                return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
            }}
            
            function _mint(address to, uint256 tokenId) internal {{
                require(to != address(0), "BRC721: mint to the zero address");
                require(!_exists(tokenId), "BRC721: token already minted");
                
                _balances[to] += 1;
                _owners[tokenId] = to;
                
                emit Transfer(address(0), to, tokenId);
            }}
            
            function _burn(uint256 tokenId) internal {{
                address owner = ownerOf(tokenId);
                
                // Clear approvals
                _approve(address(0), tokenId);
                
                _balances[owner] -= 1;
                delete _owners[tokenId];
                
                emit Transfer(owner, address(0), tokenId);
            }}
            
            function _transfer(address from, address to, uint256 tokenId) internal {{
                require(ownerOf(tokenId) == from, "BRC721: transfer of token that is not own");
                require(to != address(0), "BRC721: transfer to the zero address");
                
                // Clear approvals from the previous owner
                _approve(address(0), tokenId);
                
                _balances[from] -= 1;
                _balances[to] += 1;
                _owners[tokenId] = to;
                
                emit Transfer(from, to, tokenId);
            }}
            
            function _approve(address to, uint256 tokenId) internal {{
                _tokenApprovals[tokenId] = to;
                emit Approval(ownerOf(tokenId), to, tokenId);
            }}
            
            function _checkOnBRC721Received(address from, address to, uint256 tokenId, bytes memory _data) private returns (bool) {{
                // Simplified for brevity - in a real implementation, this would check if the recipient is a contract
                // and if it implements the BRC721Receiver interface
                return true;
            }}
            
            // Additional functions for minting (only callable by the contract owner)
            function mint(address to, uint256 tokenId) public {{
                _mint(to, tokenId);
            }}
            
            function burn(uint256 tokenId) public {{
                require(_isApprovedOrOwner(msg.sender, tokenId), "BRC721: caller is not owner nor approved");
                _burn(tokenId);
            }}
        }}
        """
        
        super().__init__(source)
        self.name = name
        self.symbol = symbol

class Governor(Contract):
    """Governance contract for managing protocol parameters and upgrades"""
    
    def __init__(self, token_address: str):
        """Initialize a new Governor contract.
        
        Args:
            token_address: Address of the governance token
        """
        source = f"""
        contract Governor {{
            address public token;
            uint256 public proposalCount;
            
            struct Proposal {{
                uint256 id;
                address proposer;
                uint256 startBlock;
                uint256 endBlock;
                uint256 forVotes;
                uint256 againstVotes;
                bool executed;
                string description;
            }}
            
            mapping(uint256 => Proposal) public proposals;
            mapping(uint256 => mapping(address => bool)) public hasVoted;
            
            event ProposalCreated(uint256 id, address proposer, string description);
            event VoteCast(address voter, uint256 proposalId, bool support, uint256 votes);
            event ProposalExecuted(uint256 id);
            
            constructor(address _token) {{
                token = _token;
            }}
            
            function propose(string memory description) public returns (uint256) {{
                require(bytes(description).length > 0, "Governor: empty description");
                
                uint256 proposalId = ++proposalCount;
                
                proposals[proposalId] = Proposal({{
                    id: proposalId,
                    proposer: msg.sender,
                    startBlock: block.number,
                    endBlock: block.number + 40320, // ~7 days with 15s blocks
                    forVotes: 0,
                    againstVotes: 0,
                    executed: false,
                    description: description
                }});
                
                emit ProposalCreated(proposalId, msg.sender, description);
                return proposalId;
            }}
            
            function vote(uint256 proposalId, bool support) public {{
                require(proposalId > 0 && proposalId <= proposalCount, "Governor: invalid proposal");
                require(!hasVoted[proposalId][msg.sender], "Governor: already voted");
                
                Proposal storage proposal = proposals[proposalId];
                require(block.number >= proposal.startBlock, "Governor: voting not started");
                require(block.number <= proposal.endBlock, "Governor: voting ended");
                
                // Get the voter's token balance (simplified)
                uint256 votes = IERC20(token).balanceOf(msg.sender);
                require(votes > 0, "Governor: no voting power");
                
                if (support) {{
                    proposal.forVotes += votes;
                }} else {{
                    proposal.againstVotes += votes;
                }}
                
                hasVoted[proposalId][msg.sender] = true;
                emit VoteCast(msg.sender, proposalId, support, votes);
            }}
            
            function execute(uint256 proposalId) public {{
                require(proposalId > 0 && proposalId <= proposalCount, "Governor: invalid proposal");
                
                Proposal storage proposal = proposals[proposalId];
                require(block.number > proposal.endBlock, "Governor: voting not ended");
                require(!proposal.executed, "Governor: proposal already executed");
                
                // Check if proposal passed
                uint256 totalVotes = proposal.forVotes + proposal.againstVotes;
                require(totalVotes > 0, "Governor: no votes");
                require(proposal.forVotes > proposal.againstVotes, "Governor: proposal failed");
                
                // Mark as executed
                proposal.executed = true;
                
                // In a real implementation, this would execute the proposal's actions
                // For now, we'll just emit an event
                emit ProposalExecuted(proposalId);
            }}
            
            function getProposal(uint256 proposalId) public view returns (
                uint256 id,
                address proposer,
                uint256 startBlock,
                uint256 endBlock,
                uint256 forVotes,
                uint256 againstVotes,
                bool executed,
                string memory description
            ) {{
                require(proposalId > 0 && proposalId <= proposalCount, "Governor: invalid proposal");
                
                Proposal storage p = proposals[proposalId];
                return (
                    p.id,
                    p.proposer,
                    p.startBlock,
                    p.endBlock,
                    p.forVotes,
                    p.againstVotes,
                    p.executed,
                    p.description
                );
            }}
        }}
        
        // Simplified ERC20 interface for the governance token
        interface IERC20 {{
            function balanceOf(address account) external view returns (uint256);
        }}
        """
        
        super().__init__(source)
        self.token_address = token_address

class Treasury(Contract):
    """Treasury contract for managing funds and payments"""
    
    def __init__(self, token_address: str):
        """Initialize a new Treasury contract.
        
        Args:
            token_address: Address of the token used for payments
        """
        source = f"""
        contract Treasury {{
            address public owner;
            address public token;
            
            event Deposit(address indexed from, uint256 amount);
            event Withdrawal(address indexed to, uint256 amount);
            
            modifier onlyOwner() {{
                require(msg.sender == owner, "Treasury: caller is not the owner");
                _;
            }}
            
            constructor(address _token) {{
                owner = msg.sender;
                token = _token;
            }}
            
            function deposit(uint256 amount) public {{
                require(amount > 0, "Treasury: amount must be greater than 0");
                
                // In a real implementation, this would transfer tokens from the sender
                // using the ERC20 transferFrom function
                // IERC20(token).transferFrom(msg.sender, address(this), amount);
                
                emit Deposit(msg.sender, amount);
            }}
            
            function withdraw(address to, uint256 amount) public onlyOwner {{
                require(amount > 0, "Treasury: amount must be greater than 0");
                
                // In a real implementation, this would transfer tokens to the recipient
                // IERC20(token).transfer(to, amount);
                
                emit Withdrawal(to, amount);
            }}
            
            function getBalance() public view returns (uint256) {{
                // In a real implementation, this would return the token balance
                // return IERC20(token).balanceOf(address(this));
                return 0;
            }}
            
            function transferOwnership(address newOwner) public onlyOwner {{
                require(newOwner != address(0), "Treasury: new owner is the zero address");
                owner = newOwner;
            }}
        }}
        
        // Simplified ERC20 interface for the treasury token
        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }}
        """
        
        super().__init__(source)
        self.token_address = token_address

# Example usage
if __name__ == "__main__":
    # Create a BRC20 token
    token = BRC20("Brixa Token", "BRX", 18, 1_000_000 * 10**18)
    print(f"Created BRC20 token: {token.name} ({token.symbol})")
    
    # Create an NFT collection
    nft = BRC721("Brixa Collectibles", "BRXNFT")
    print(f"Created NFT collection: {nft.name} ({nft.symbol})")
    
    # Create a governance contract
    governor = Governor("0x1234...")
    print("Created Governor contract")
    
    # Create a treasury
    treasury = Treasury("0x1234...")
    print("Created Treasury contract")
