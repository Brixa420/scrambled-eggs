# Blockchain Deployment Guide

This guide explains how to deploy and verify the Brixa smart contracts.

## Prerequisites

1. Node.js (v14 or later)
2. npm or yarn
3. Hardhat
4. MetaMask or another Web3 wallet
5. Testnet MATIC (for Mumbai) or MATIC (for Polygon Mainnet)

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Copy `.env.example` to `.env` and fill in your details:
   ```bash
   cp .env.example .env
   ```

3. Add your private key and API keys to `.env`

## Deployment

### Local Development

1. Start a local Hardhat node:
   ```bash
   npx hardhat node
   ```

2. In a new terminal, deploy to localhost:
   ```bash
   npx hardhat run scripts/deploy.js --network localhost
   ```

### Testnet (Mumbai)

1. Make sure you have testnet MATIC in your wallet
2. Deploy to Mumbai testnet:
   ```bash
   npx hardhat run scripts/deploy.js --network mumbai
   ```

### Mainnet (Polygon)

1. Make sure you have MATIC in your wallet
2. Deploy to Polygon mainnet:
   ```bash
   npx hardhat run scripts/deploy.js --network polygon
   ```

## Verifying Contracts

Contracts are automatically verified if you have set up your `POLYGONSCAN_API_KEY` in `.env`.

To manually verify a contract:

```bash
npx hardhat verify --network mumbai DEPLOYED_CONTRACT_ADDRESS "Constructor argument 1"
```

## Interacting with Contracts

Use the Hardhat console to interact with deployed contracts:

```bash
npx hardhat console --network mumbai
> const contract = await ethers.getContractAt("ContractName", "CONTRACT_ADDRESS")
> await contract.someFunction()
```

## Environment Variables

- `MUMBAI_RPC_URL`: RPC URL for Mumbai testnet
- `POLYGON_RPC_URL`: RPC URL for Polygon mainnet
- `PRIVATE_KEY`: Your wallet's private key (without 0x)
- `POLYGONSCAN_API_KEY`: API key for Polygonscan verification
- `COINMARKETCAP_API_KEY`: API key for gas price estimation (optional)

## Security

- Never commit your `.env` file
- Use a dedicated wallet for deployment
- Consider using a hardware wallet for mainnet deployments
- Always verify your contracts on Polygonscan

## Troubleshooting

- If you get "nonce too low", reset your wallet nonce
- For out of gas errors, increase the gas limit in the deployment script
- If verification fails, check for any constructor arguments that need to be passed
