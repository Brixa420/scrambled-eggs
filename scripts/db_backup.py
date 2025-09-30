"""Database backup and recovery utilities."""

import asyncio
import datetime
import gzip
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.db.session import async_engine


class DatabaseBackup:
    """Handles database backup and recovery operations."""
    
    def __init__(self):
        """Initialize the backup utility."""
        self.backup_dir = Path(settings.BACKUP_DIR) / "database"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    async def create_backup(self, tag: Optional[str] = None) -> str:
        """Create a backup of the database.
        
        Args:
            tag: Optional tag to include in the backup filename
            
        Returns:
            Path to the created backup file
        """
        # Generate backup filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        tag_suffix = f"_{tag}" if tag else ""
        backup_file = self.backup_dir / f"backup_{timestamp}{tag_suffix}.sql.gz"
        
        # Get database connection string
        db_url = str(settings.DATABASE_URL)
        
        # Create backup using pg_dump for PostgreSQL or sqlite3 for SQLite
        if db_url.startswith("postgresql"):
            # PostgreSQL backup
            cmd = [
                "pg_dump",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--no-comments",
                "--dbname", db_url
            ]
            
            with gzip.open(backup_file, 'wb') as f:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Stream the output to the gzip file
                while True:
                    data = await process.stdout.read(4096)
                    if not data:
                        break
                    f.write(data)
                
                # Wait for the process to complete
                await process.wait()
                
                if process.returncode != 0:
                    stderr = await process.stderr.read()
                    raise Exception(f"Backup failed: {stderr.decode()}")
                    
        else:  # SQLite
            db_path = db_url.replace("sqlite:///", "")
            with gzip.open(backup_file, 'wb') as f_out:
                with open(db_path, 'rb') as f_in:
                    shutil.copyfileobj(f_in, f_out)
        
        print(f"Backup created: {backup_file}")
        return str(backup_file)
    
    async def restore_backup(self, backup_file: str) -> None:
        """Restore the database from a backup.
        
        Args:
            backup_file: Path to the backup file to restore from
        """
        if not os.path.exists(backup_file):
            raise FileNotFoundError(f"Backup file not found: {backup_file}")
        
        # Get database connection string
        db_url = str(settings.DATABASE_URL)
        
        if db_url.startswith("postgresql"):
            # PostgreSQL restore
            cmd = [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--dbname", db_url
            ]
            
            with gzip.open(backup_file, 'rb') as f:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Stream the input from the gzip file
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    process.stdin.write(data)
                    await process.stdin.drain()
                
                # Close stdin and wait for the process to complete
                process.stdin.close()
                await process.wait()
                
                if process.returncode != 0:
                    stderr = await process.stderr.read()
                    raise Exception(f"Restore failed: {stderr.decode()}")
                    
        else:  # SQLite
            # Close any existing connections
            await async_engine.dispose()
            
            # Restore the database file
            db_path = db_url.replace("sqlite:///", "")
            with gzip.open(backup_file, 'rb') as f_in:
                with open(db_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Recreate the engine
            from app.db.session import create_engine
            global async_engine
            async_engine = create_engine()
        
        print(f"Database restored from backup: {backup_file}")
    
    def list_backups(self) -> list:
        """List all available backups.
        
        Returns:
            List of backup files, sorted by modification time (newest first)
        """
        backups = []
        for file in self.backup_dir.glob("backup_*.sql.gz"):
            stats = file.stat()
            backups.append({
                'path': str(file),
                'name': file.name,
                'size': stats.st_size,
                'modified': datetime.datetime.fromtimestamp(stats.st_mtime)
            })
        
        # Sort by modification time (newest first)
        return sorted(backups, key=lambda x: x['modified'], reverse=True)
    
    async def schedule_daily_backup(self) -> None:
        """Schedule a daily backup (to be called from a cron job or similar)."""
        await self.create_backup("daily")
        
        # Keep only the last 7 daily backups
        backups = self.list_backups()
        daily_backups = [b for b in backups if "_daily" in b['name']]
        
        if len(daily_backups) > 7:
            for backup in daily_backups[7:]:
                try:
                    os.remove(backup['path'])
                    print(f"Removed old backup: {backup['name']}")
                except Exception as e:
                    print(f"Error removing backup {backup['name']}: {e}")


async def main():
    """Command-line interface for database backup/restore."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database backup and recovery utility")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Create backup command
    backup_parser = subparsers.add_parser('backup', help='Create a database backup')
    backup_parser.add_argument('--tag', help='Tag to include in the backup filename')
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore database from backup')
    restore_parser.add_argument('backup_file', help='Path to the backup file to restore')
    
    # List command
    subparsers.add_parser('list', help='List available backups')
    
    # Schedule command
    schedule_parser = subparsers.add_parser('schedule', help='Schedule a daily backup')
    
    args = parser.parse_args()
    backup = DatabaseBackup()
    
    try:
        if args.command == 'backup':
            backup_file = await backup.create_backup(args.tag)
            print(f"Backup created: {backup_file}")
            
        elif args.command == 'restore':
            confirm = input("WARNING: This will overwrite the current database. Continue? (y/N) ")
            if confirm.lower() == 'y':
                await backup.restore_backup(args.backup_file)
                print("Database restored successfully")
            else:
                print("Restore cancelled")
                
        elif args.command == 'list':
            backups = backup.list_backups()
            if not backups:
                print("No backups found")
                return
                
            print(f"\n{'Date':<20} {'Size (MB)':>10} {'Name'}")
            print("-" * 60)
            for backup in backups:
                print(f"{backup['modified'].strftime('%Y-%m-%d %H:%M:%S')}  "
                      f"{backup['size'] / (1024*1024):>8.2f}  {backup['name']}")
            print()
            
        elif args.command == 'schedule':
            await backup.schedule_daily_backup()
            print("Daily backup completed")
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
