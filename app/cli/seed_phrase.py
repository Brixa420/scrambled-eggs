"""
Seed Phrase Management CLI

This module provides a command-line interface for securely managing Brixa wallet seed phrases.
"""
import os
import sys
import getpass
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services.security.seed_manager import SeedManager, SeedManager

console = Console()

def print_warning():
    """Display a prominent warning about seed phrase security."""
    warning_text = Text(
        "IMPORTANT: WRITE DOWN YOUR SEED PHRASE AND STORE IT SECURELY\n\n"
        "Your seed phrase is the ONLY way to recover your Brixa wallet.\n"
        "If you lose your seed phrase, you will permanently lose access to your funds.\n\n"
        "• Write it down on paper and store it in a secure location\n"
        "• Never share your seed phrase with anyone\n"
        "• Never store it digitally in plain text\n"
        "• Consider using a hardware wallet for large amounts\n\n"
        "The security of your funds depends on keeping this information private.",
        style="bold red"
    )
    
    console.print(Panel(
        warning_text,
        title="[bold red]SECURITY WARNING[/bold red]",
        border_style="red",
        padding=(1, 2)
    ))

def get_password(confirm: bool = False) -> str:
    """Securely get a password from the user with optional confirmation.
    
    Args:
        confirm: If True, prompt for password confirmation
        
    Returns:
        str: The entered password
    """
    while True:
        password = getpass.getpass("Enter a strong password (min 12 chars): ")
        
        if len(password) < 12:
            console.print("[red]Error:[/] Password must be at least 12 characters long")
            continue
            
        if not confirm:
            return password
            
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password == confirm_password:
            return password
            
        console.print("[red]Error:[/] Passwords do not match. Please try again.")

def print_seed_phrase(seed_phrase: str):
    """Display the seed phrase in a secure way."""
    words = seed_phrase.split()
    word_groups = [words[i:i+4] for i in range(0, len(words), 4)]
    
    console.print("\n[bold green]Your Brixa Seed Phrase:[/]\n")
    
    for i, group in enumerate(word_groups, 1):
        line = "  ".join(f"[bold]{i + j*len(word_groups)}. {word}" 
                        for j, word in enumerate(group))
        console.print(f"  {line}")
    
    console.print("\n[bold]IMPORTANT:[/] Write down your seed phrase and store it in a secure location.\n")

@click.group()
def seed():
    """Manage Brixa wallet seed phrases securely."""
    pass

def verify_seed_phrase(seed_phrase: str, attempts: int = 3) -> bool:
    """Verify that the user has correctly written down their seed phrase."""
    words = seed_phrase.split()
    
    # Select 3 random words to verify (but at least 25% of the total words)
    import random
    num_to_verify = max(3, len(words) // 4)
    indices = sorted(random.sample(range(len(words)), num_to_verify))
    
    console.print("\n[bold yellow]VERIFICATION REQUIRED[/]")
    console.print("To ensure you've saved your seed phrase correctly, please enter the following words:")
    
    for attempt in range(attempts, 0, -1):
        correct = True
        entered_words = []
        
        for i, idx in enumerate(indices, 1):
            # Show the position (1-based) and first letter as hint
            hint = words[idx][0] if len(words[idx]) > 1 else ''
            word = click.prompt(f"\nEnter word #{idx + 1} (starts with '{hint}...')", type=str).strip().lower()
            
            if word != words[idx]:
                correct = False
                if attempt > 1:
                    console.print(f"[red]Incorrect. {attempt - 1} attempts remaining.[/]")
                break
            
            entered_words.append((idx, word))
        
        if correct:
            # Show which words were correct
            console.print("\n[green]✓ Verification successful![/]")
            for idx, word in entered_words:
                console.print(f"  Word #{idx + 1}: [green]{word}[/]")
            return True
        
        if attempt <= 1:
            console.print("\n[red]Verification failed. Please start over with a new seed phrase.[/]")
            return False
    
    return False

@seed.command()
@click.option('--strength', type=click.IntRange(128, 256), default=256,
              help='Bit strength (128, 160, 192, 224, or 256)')
@click.option('--wallet-id', help='Wallet identifier (default: generated)')
@click.option('--skip-verification', is_flag=True, help='Skip seed phrase verification (not recommended)')
def generate(strength: int, wallet_id: Optional[str] = None, skip_verification: bool = False):
    """Generate a new secure seed phrase."""
    try:
        # Generate a wallet ID if not provided
        if not wallet_id:
            import uuid
            wallet_id = f"wallet_{uuid.uuid4().hex[:8]}"
        
        # Display security warning
        print_warning()
        
        # Get a secure password
        console.print("\n[bold]Create a strong password to encrypt your seed phrase[/]")
        password = get_password(confirm=True)
        
        # Generate and display the seed phrase
        manager = SeedManager()
        seed_phrase = manager.generate_seed_phrase(strength)
        
        # Save the seed phrase securely (temporarily)
        temp_save_path = manager.storage_path / f"{wallet_id}.tmp"
        with open(temp_save_path, 'w') as f:
            f.write(seed_phrase)
        temp_save_path.chmod(0o600)  # Restrictive permissions
        
        try:
            # Display the seed phrase to the user
            console.print("\n[bold green]✓ Seed phrase generated[/]")
            console.print(f"Wallet ID: [bold]{wallet_id}[/]\n")
            
            print_seed_phrase(seed_phrase)
            
            console.print("\n[bold yellow]IMPORTANT:[/]")
            console.print("1. Write down your seed phrase on paper")
            console.print("2. Store it in a secure, offline location")
            console.print("3. Never share it with anyone")
            console.print("4. This is the ONLY time you'll see your full seed phrase")
            
            if not skip_verification:
                console.print("\n[bold]Press Enter when you've written down your seed phrase...[/]")
                input()
                
                # Verify the user has saved the seed phrase correctly
                if not verify_seed_phrase(seed_phrase):
                    raise click.Abort()
            
            # Save the seed phrase permanently
            save_path = manager.save_seed_phrase(wallet_id, seed_phrase, password)
            console.print(f"\n[green]✓ Seed phrase saved securely to:[/] [dim]{save_path}[/]")
            
        finally:
            # Clean up temporary file
            if temp_save_path.exists():
                # Securely wipe the temporary file
                with open(temp_save_path, 'wb') as f:
                    f.write(os.urandom(len(seed_phrase)))
                temp_save_path.unlink()
        
    except Exception as e:
        console.print(f"[red]Error:[/] {str(e)}", err=True)
        sys.exit(1)

@seed.command()
@click.argument('wallet_id')
def show(wallet_id: str):
    """Show a previously saved seed phrase."""
    try:
        # Get the password
        password = getpass.getpass(f"Enter password for wallet '{wallet_id}': ")
        
        # Load and decrypt the seed phrase
        manager = SeedManager()
        seed_phrase = manager.load_seed_phrase(wallet_id, password)
        
        # Display the seed phrase with security warning
        print_warning()
        print_seed_phrase(seed_phrase)
        
    except Exception as e:
        console.print(f"[red]Error:[/] {str(e)}", err=True)
        sys.exit(1)

@seed.command()
@click.argument('wallet_id')
def delete(wallet_id: str):
    """Securely delete a saved seed phrase."""
    try:
        # Confirm deletion
        if not click.confirm(f"Are you sure you want to delete the seed phrase for wallet '{wallet_id}'?"):
            console.print("Operation cancelled.")
            return
            
        # Delete the seed phrase
        manager = SeedManager()
        if manager.delete_seed_phrase(wallet_id):
            console.print(f"[green]✓ Seed phrase for wallet '{wallet_id}' has been securely deleted.[/]")
        else:
            console.print(f"[yellow]No seed phrase found for wallet '{wallet_id}'[/]")
            
    except Exception as e:
        console.print(f"[red]Error:[/] {str(e)}", err=True)
        sys.exit(1)

@seed.command(name='list')
def list_wallets():
    """List all saved wallet IDs."""
    try:
        manager = SeedManager()
        wallets = manager.get_wallet_list()
        
        if not wallets:
            console.print("No saved wallets found.")
            return
            
        console.print("[bold]Saved Wallets:[/]")
        for wallet in wallets:
            console.print(f"• {wallet}")
            
    except Exception as e:
        console.print(f"[red]Error:[/] {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    seed()
