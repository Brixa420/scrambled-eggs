# mine_block.py
from brixa.cli.main import BrixaCLI
import asyncio

async def mine():
    cli = BrixaCLI()
    cli.current_wallet = await cli.load_wallet('1JEEm6V74SSikttwWZkNkVf7kAtpNwbDeo')
    if cli.current_wallet:
        print("Wallet loaded successfully!")
        await cli.mine_block()
    else:
        print("Failed to load wallet.")

if __name__ == "__main__":
    asyncio.run(mine())
