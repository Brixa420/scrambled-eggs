"""
Disaster Recovery Module for Cloud HSM

This module provides disaster recovery features for the Cloud HSM client,
including backup/restore, failover, and data replication.
"""

import asyncio
import gzip
import hashlib
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Cloud storage providers
try:
    import boto3
    from azure.storage.blob import BlobServiceClient
    from google.cloud import storage

    CLOUD_STORAGE_AVAILABLE = True
except ImportError:
    CLOUD_STORAGE_AVAILABLE = False


class BackupType(Enum):
    """Types of backups."""

    FULL = "full"  # Complete backup of all data
    INCREMENTAL = "incr"  # Incremental backup (changes since last backup)
    DIFFERENTIAL = "diff"  # Differential backup (changes since last full backup)


class StorageProvider(Enum):
    """Supported storage providers for backups."""

    LOCAL = "local"  # Local filesystem
    S3 = "s3"  # Amazon S3
    GCS = "gcs"  # Google Cloud Storage
    AZURE = "azure"  # Azure Blob Storage


class RecoveryPointObjective(Enum):
    """Recovery Point Objective (RPO) levels."""

    MINUTES_15 = 15 * 60
    HOURLY = 3600
    DAILY = 86400
    WEEKLY = 604800
    MONTHLY = 2592000


class RecoveryTimeObjective(Enum):
    """Recovery Time Objective (RTO) levels."""

    MINUTES_5 = 300
    MINUTES_15 = 900
    HOURLY = 3600
    DAILY = 86400


@dataclass
class BackupConfig:
    """Configuration for backup operations."""

    provider: StorageProvider
    location: str
    retention_days: int = 30
    encryption_key: Optional[bytes] = None
    compression: bool = True
    max_backups: int = 10
    schedule: str = "0 0 * * *"  # Default: daily at midnight
    rpo: RecoveryPointObjective = RecoveryPointObjective.DAILY
    rto: RecoveryTimeObjective = RecoveryTimeObjective.HOURLY


@dataclass
class RecoveryPoint:
    """Represents a recovery point (backup)."""

    id: str
    timestamp: float
    backup_type: BackupType
    size_bytes: int
    checksum: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "backup_type": self.backup_type.value,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RecoveryPoint":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            timestamp=data["timestamp"],
            backup_type=BackupType(data["backup_type"]),
            size_bytes=data["size_bytes"],
            checksum=data["checksum"],
            metadata=data.get("metadata", {}),
        )


class DisasterRecoveryManager:
    """
    Manages disaster recovery operations for the Cloud HSM.
    """

    def __init__(self, config: BackupConfig, logger: logging.Logger = None):
        """
        Initialize the disaster recovery manager.

        Args:
            config: Backup configuration
            logger: Logger instance (optional)
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.backup_in_progress = False
        self.last_backup_time = 0
        self.recovery_points: List[RecoveryPoint] = []
        self._load_recovery_points()

    async def create_backup(
        self,
        backup_type: BackupType = BackupType.FULL,
        data: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[RecoveryPoint]:
        """
        Create a backup of the current state.

        Args:
            backup_type: Type of backup to create
            data: Data to back up (if None, will collect from HSM)
            **kwargs: Additional options for the backup

        Returns:
            RecoveryPoint if backup was successful, None otherwise
        """
        if self.backup_in_progress:
            self.logger.warning("Backup already in progress")
            return None

        self.backup_in_progress = True
        start_time = time.time()

        try:
            # Generate a unique backup ID
            backup_id = f"backup_{int(start_time)}_{backup_type.value}"

            # If no data provided, collect from HSM
            if data is None:
                data = await self._collect_backup_data()

            # Serialize data to JSON
            json_data = json.dumps(data).encode("utf-8")

            # Compress the data
            if self.config.compression:
                compressed_data = gzip.compress(json_data)
                backup_data = compressed_data
            else:
                backup_data = json_data

            # Encrypt the data if a key is provided
            if self.config.encryption_key:
                backup_data = self._encrypt_data(backup_data, self.config.encryption_key)

            # Calculate checksum
            checksum = hashlib.sha256(backup_data).hexdigest()

            # Create backup metadata
            backup_metadata = {
                "version": "1.0",
                "timestamp": start_time,
                "backup_type": backup_type.value,
                "compression": self.config.compression,
                "encrypted": self.config.encryption_key is not None,
                "size": len(backup_data),
                "checksum": checksum,
                "config": {
                    "provider": self.config.provider.value,
                    "location": self.config.location,
                    "rpo": self.config.rpo.value,
                    "rto": self.config.rto.value,
                },
                "system": {
                    "platform": os.name,
                    "python_version": ".".join(map(str, sys.version_info[:3])),
                },
                **kwargs.get("metadata", {}),
            }

            # Create a temporary directory for the backup
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)

                # Write the backup data
                backup_file = temp_dir_path / f"{backup_id}.bin"
                with open(backup_file, "wb") as f:
                    f.write(backup_data)

                # Write the metadata
                metadata_file = temp_dir_path / f"{backup_id}.json"
                with open(metadata_file, "w") as f:
                    json.dump(backup_metadata, f, indent=2)

                # Create a tarball of the backup
                backup_tar = temp_dir_path / f"{backup_id}.tar.gz"
                with tarfile.open(backup_tar, "w:gz") as tar:
                    tar.add(backup_file, arcname=f"{backup_id}.bin")
                    tar.add(metadata_file, arcname=f"{backup_id}.json")

                # Upload the backup to the storage provider
                backup_size = backup_tar.stat().st_size
                await self._upload_backup(backup_tar, f"{backup_id}.tar.gz")

            # Create a recovery point
            recovery_point = RecoveryPoint(
                id=backup_id,
                timestamp=start_time,
                backup_type=backup_type,
                size_bytes=backup_size,
                checksum=checksum,
                metadata=backup_metadata,
            )

            # Add to the list of recovery points
            self.recovery_points.append(recovery_point)
            self.last_backup_time = start_time

            # Clean up old backups
            await self._cleanup_old_backups()

            # Save the updated recovery points
            self._save_recovery_points()

            self.logger.info(
                f"Created {backup_type.value} backup {backup_id} "
                f"({backup_size / (1024*1024):.2f} MB) in {time.time() - start_time:.2f}s"
            )

            return recovery_point

        except Exception as e:
            self.logger.error(f"Backup failed: {str(e)}", exc_info=True)
            return None

        finally:
            self.backup_in_progress = False

    async def restore_backup(
        self, recovery_point_id: str, target_location: Optional[str] = None, **kwargs
    ) -> bool:
        """
        Restore from a specific recovery point.

        Args:
            recovery_point_id: ID of the recovery point to restore from
            target_location: Optional target location for the restored data
            **kwargs: Additional options for the restore

        Returns:
            True if the restore was successful, False otherwise
        """
        start_time = time.time()

        try:
            # Find the recovery point
            recovery_point = next(
                (rp for rp in self.recovery_points if rp.id == recovery_point_id), None
            )

            if not recovery_point:
                self.logger.error(f"Recovery point {recovery_point_id} not found")
                return False

            self.logger.info(f"Starting restore from recovery point {recovery_point_id}")

            # Download the backup
            backup_file = await self._download_backup(f"{recovery_point_id}.tar.gz")
            if not backup_file:
                return False

            # Extract the backup
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)

                # Extract the tarball
                with tarfile.open(backup_file, "r:gz") as tar:
                    tar.extractall(path=temp_dir_path)

                # Read the metadata
                metadata_file = temp_dir_path / f"{recovery_point_id}.json"
                with open(metadata_file, "r") as f:
                    metadata = json.load(f)

                # Read the backup data
                data_file = temp_dir_path / f"{recovery_point_id}.bin"
                with open(data_file, "rb") as f:
                    backup_data = f.read()

                # Verify the checksum
                checksum = hashlib.sha256(backup_data).hexdigest()
                if checksum != recovery_point.checksum:
                    self.logger.error("Checksum verification failed")
                    return False

                # Decrypt the data if it was encrypted
                if metadata.get("encrypted", False):
                    if not self.config.encryption_key:
                        self.logger.error("Backup is encrypted but no encryption key was provided")
                        return False

                    backup_data = self._decrypt_data(backup_data, self.config.encryption_key)

                # Decompress the data if it was compressed
                if metadata.get("compression", False):
                    backup_data = gzip.decompress(backup_data)

                # Parse the JSON data
                data = json.loads(backup_data.decode("utf-8"))

                # Restore the data
                await self._restore_data(data, target_location, **kwargs)

            self.logger.info(
                f"Restore from recovery point {recovery_point_id} completed "
                f"in {time.time() - start_time:.2f}s"
            )

            return True

        except Exception as e:
            self.logger.error(f"Restore failed: {str(e)}", exc_info=True)
            return False

    async def list_recovery_points(
        self, limit: int = 100, offset: int = 0, backup_type: Optional[BackupType] = None
    ) -> List[RecoveryPoint]:
        """
        List available recovery points.

        Args:
            limit: Maximum number of recovery points to return
            offset: Offset for pagination
            backup_type: Optional filter by backup type

        Returns:
            List of recovery points
        """
        points = self.recovery_points

        # Filter by backup type if specified
        if backup_type is not None:
            points = [p for p in points if p.backup_type == backup_type]

        # Sort by timestamp (newest first)
        points.sort(key=lambda p: p.timestamp, reverse=True)

        # Apply pagination
        return points[offset : offset + limit]

    async def get_recovery_point(self, recovery_point_id: str) -> Optional[RecoveryPoint]:
        """
        Get a specific recovery point by ID.

        Args:
            recovery_point_id: ID of the recovery point to retrieve

        Returns:
            The recovery point, or None if not found
        """
        for point in self.recovery_points:
            if point.id == recovery_point_id:
                return point
        return None

    async def delete_recovery_point(self, recovery_point_id: str) -> bool:
        """
        Delete a recovery point.

        Args:
            recovery_point_id: ID of the recovery point to delete

        Returns:
            True if the recovery point was deleted, False otherwise
        """
        # Find the recovery point
        for i, point in enumerate(self.recovery_points):
            if point.id == recovery_point_id:
                # Remove from storage
                await self._delete_backup(f"{recovery_point_id}.tar.gz")

                # Remove from the list
                del self.recovery_points[i]
                self._save_recovery_points()

                self.logger.info(f"Deleted recovery point {recovery_point_id}")
                return True

        self.logger.warning(f"Recovery point {recovery_point_id} not found")
        return False

    async def schedule_backups(self) -> None:
        """
        Schedule periodic backups based on the configuration.

        This method should be called once at startup to enable scheduled backups.
        """
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            from apscheduler.triggers.cron import CronTrigger

            # Create a scheduler
            self.scheduler = AsyncIOScheduler()

            # Parse the cron schedule
            try:
                # Simple cron format parsing (minute hour day month day_of_week)
                minute, hour, day, month, day_of_week = self.config.schedule.split()

                # Add the job
                self.scheduler.add_job(
                    self.create_backup,
                    CronTrigger(
                        minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week
                    ),
                    args=[BackupType.FULL],
                    kwargs={"scheduled": True},
                )

                self.logger.info(f"Scheduled backups with cron: {self.config.schedule}")
                self.scheduler.start()

            except (ValueError, IndexError):
                self.logger.error(
                    "Invalid backup schedule format. Use 'minute hour day month day_of_week'"
                )

        except ImportError:
            self.logger.warning("APScheduler not installed. Scheduled backups are disabled.")

    async def _collect_backup_data(self) -> Dict[str, Any]:
        """
        Collect data to be backed up from the HSM.

        Returns:
            Dictionary containing the backup data
        """
        # In a real implementation, this would collect data from the HSM
        # For now, we'll return a simple example
        return {
            "timestamp": time.time(),
            "data": {
                "keys": [],  # List of key metadata
                "policies": [],  # List of security policies
                "users": [],  # List of users and permissions
                "config": {},  # System configuration
            },
            "metadata": {
                "version": "1.0",
                "backup_type": "full",
                "created_by": "system",
                "system_info": {
                    "platform": os.name,
                    "python_version": ".".join(map(str, sys.version_info[:3])),
                },
            },
        }

    async def _restore_data(
        self, data: Dict[str, Any], target_location: Optional[str] = None, **kwargs
    ) -> bool:
        """
        Restore data from a backup.

        Args:
            data: The data to restore
            target_location: Optional target location for the restored data
            **kwargs: Additional options for the restore

        Returns:
            True if the restore was successful, False otherwise
        """
        # In a real implementation, this would restore the data to the HSM
        # For now, we'll just log the operation
        self.logger.info(f"Restoring data from backup (size: {len(str(data))} bytes)")

        # Simulate the restore process
        await asyncio.sleep(1)

        self.logger.info("Data restore completed successfully")
        return True

    async def _upload_backup(self, local_path: Path, remote_path: str) -> bool:
        """
        Upload a backup file to the storage provider.

        Args:
            local_path: Path to the local file
            remote_path: Path in the storage provider

        Returns:
            True if the upload was successful, False otherwise
        """
        try:
            if self.config.provider == StorageProvider.LOCAL:
                # For local storage, just copy the file
                dest_path = Path(self.config.location) / remote_path
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(local_path, dest_path)

            elif self.config.provider == StorageProvider.S3 and CLOUD_STORAGE_AVAILABLE:
                # For S3, use boto3
                s3 = boto3.client("s3")
                bucket, key = self._parse_s3_uri(self.config.location)
                s3.upload_file(str(local_path), bucket, f"{key}/{remote_path}")

            elif self.config.provider == StorageProvider.GCS and CLOUD_STORAGE_AVAILABLE:
                # For Google Cloud Storage
                client = storage.Client()
                bucket_name, prefix = self._parse_gcs_uri(self.config.location)
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(f"{prefix}/{remote_path}" if prefix else remote_path)
                blob.upload_from_filename(str(local_path))

            elif self.config.provider == StorageProvider.AZURE and CLOUD_STORAGE_AVAILABLE:
                # For Azure Blob Storage
                container_name, prefix = self._parse_azure_uri(self.config.location)
                blob_service_client = BlobServiceClient.from_connection_string(
                    self.config.azure_connection_string
                )
                blob_client = blob_service_client.get_blob_client(
                    container=container_name,
                    blob=f"{prefix}/{remote_path}" if prefix else remote_path,
                )
                with open(local_path, "rb") as data:
                    blob_client.upload_blob(data, overwrite=True)

            else:
                raise ValueError(f"Unsupported storage provider: {self.config.provider}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to upload backup: {str(e)}")
            return False

    async def _download_backup(self, remote_path: str) -> Optional[Path]:
        """
        Download a backup file from the storage provider.

        Args:
            remote_path: Path in the storage provider

        Returns:
            Path to the downloaded file, or None if the download failed
        """
        try:
            # Create a temporary file
            temp_file = Path(tempfile.mktemp(suffix=".tar.gz"))

            if self.config.provider == StorageProvider.LOCAL:
                # For local storage, just copy the file
                src_path = Path(self.config.location) / remote_path
                shutil.copy2(src_path, temp_file)

            elif self.config.provider == StorageProvider.S3 and CLOUD_STORAGE_AVAILABLE:
                # For S3, use boto3
                s3 = boto3.client("s3")
                bucket, key = self._parse_s3_uri(self.config.location)
                s3.download_file(bucket, f"{key}/{remote_path}", str(temp_file))

            elif self.config.provider == StorageProvider.GCS and CLOUD_STORAGE_AVAILABLE:
                # For Google Cloud Storage
                client = storage.Client()
                bucket_name, prefix = self._parse_gcs_uri(self.config.location)
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(f"{prefix}/{remote_path}" if prefix else remote_path)
                blob.download_to_filename(str(temp_file))

            elif self.config.provider == StorageProvider.AZURE and CLOUD_STORAGE_AVAILABLE:
                # For Azure Blob Storage
                container_name, prefix = self._parse_azure_uri(self.config.location)
                blob_service_client = BlobServiceClient.from_connection_string(
                    self.config.azure_connection_string
                )
                blob_client = blob_service_client.get_blob_client(
                    container=container_name,
                    blob=f"{prefix}/{remote_path}" if prefix else remote_path,
                )
                with open(temp_file, "wb") as f:
                    f.write(blob_client.download_blob().readall())

            else:
                raise ValueError(f"Unsupported storage provider: {self.config.provider}")

            return temp_file

        except Exception as e:
            self.logger.error(f"Failed to download backup: {str(e)}")
            if temp_file.exists():
                temp_file.unlink()
            return None

    async def _delete_backup(self, remote_path: str) -> bool:
        """
        Delete a backup file from the storage provider.

        Args:
            remote_path: Path in the storage provider

        Returns:
            True if the deletion was successful, False otherwise
        """
        try:
            if self.config.provider == StorageProvider.LOCAL:
                # For local storage, just delete the file
                file_path = Path(self.config.location) / remote_path
                file_path.unlink()

            elif self.config.provider == StorageProvider.S3 and CLOUD_STORAGE_AVAILABLE:
                # For S3, use boto3
                s3 = boto3.client("s3")
                bucket, key = self._parse_s3_uri(self.config.location)
                s3.delete_object(Bucket=bucket, Key=f"{key}/{remote_path}")

            elif self.config.provider == StorageProvider.GCS and CLOUD_STORAGE_AVAILABLE:
                # For Google Cloud Storage
                client = storage.Client()
                bucket_name, prefix = self._parse_gcs_uri(self.config.location)
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(f"{prefix}/{remote_path}" if prefix else remote_path)
                blob.delete()

            elif self.config.provider == StorageProvider.AZURE and CLOUD_STORAGE_AVAILABLE:
                # For Azure Blob Storage
                container_name, prefix = self._parse_azure_uri(self.config.location)
                blob_service_client = BlobServiceClient.from_connection_string(
                    self.config.azure_connection_string
                )
                blob_client = blob_service_client.get_blob_client(
                    container=container_name,
                    blob=f"{prefix}/{remote_path}" if prefix else remote_path,
                )
                blob_client.delete_blob()

            else:
                raise ValueError(f"Unsupported storage provider: {self.config.provider}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to delete backup: {str(e)}")
            return False

    async def _cleanup_old_backups(self) -> None:
        """Clean up old backups based on retention policy."""
        if not self.recovery_points or self.config.retention_days <= 0:
            return

        # Sort recovery points by timestamp (oldest first)
        sorted_points = sorted(self.recovery_points, key=lambda p: p.timestamp)

        # Calculate the cutoff time
        cutoff_time = time.time() - (self.config.retention_days * 24 * 3600)

        # Keep track of the most recent full backup
        last_full_backup = None

        for point in sorted_points:
            # Skip if the point is newer than the cutoff
            if point.timestamp > cutoff_time:
                continue

            # Skip if this is the most recent full backup
            if point.backup_type == BackupType.FULL:
                if last_full_backup is None:
                    last_full_backup = point
                    continue

                # If we already have a full backup, delete this one
                await self.delete_recovery_point(point.id)

            # For incremental/differential backups, only keep them if they're after the last full backup
            elif last_full_backup and point.timestamp > last_full_backup.timestamp:
                continue
            else:
                await self.delete_recovery_point(point.id)

        # Enforce the maximum number of backups
        if self.config.max_backups > 0 and len(self.recovery_points) > self.config.max_backups:
            # Sort by timestamp (oldest first) and delete the excess
            sorted_points = sorted(self.recovery_points, key=lambda p: p.timestamp)
            for point in sorted_points[: -self.config.max_backups]:
                await self.delete_recovery_point(point.id)

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM.

        Args:
            data: Data to encrypt
            key: Encryption key (must be 32 bytes for AES-256)

        Returns:
            Encrypted data with nonce and tag
        """
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Generate a random 96-bit nonce
        nonce = os.urandom(12)

        # Encrypt the data
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)

        # Return nonce + ciphertext + tag
        return nonce + ct

    def _decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            data: Encrypted data (nonce + ciphertext + tag)
            key: Encryption key (must be 32 bytes for AES-256)

        Returns:
            Decrypted data
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Split the data into nonce, ciphertext, and tag
        nonce = data[:12]
        ct = data[12:]

        # Decrypt the data
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

    def _load_recovery_points(self) -> None:
        """Load the list of recovery points from disk."""
        try:
            state_file = Path(self.config.location) / "recovery_points.json"
            if state_file.exists():
                with open(state_file, "r") as f:
                    data = json.load(f)
                    self.recovery_points = [
                        RecoveryPoint.from_dict(p) for p in data.get("recovery_points", [])
                    ]
                    self.last_backup_time = data.get("last_backup_time", 0)
        except Exception as e:
            self.logger.error(f"Failed to load recovery points: {str(e)}")
            self.recovery_points = []
            self.last_backup_time = 0

    def _save_recovery_points(self) -> None:
        """Save the list of recovery points to disk."""
        try:
            state_file = Path(self.config.location) / "recovery_points.json"
            state_file.parent.mkdir(parents=True, exist_ok=True)

            with open(state_file, "w") as f:
                json.dump(
                    {
                        "recovery_points": [p.to_dict() for p in self.recovery_points],
                        "last_backup_time": self.last_backup_time,
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            self.logger.error(f"Failed to save recovery points: {str(e)}")

    @staticmethod
    def _parse_s3_uri(uri: str) -> Tuple[str, str]:
        """Parse an S3 URI into bucket and prefix."""
        if not uri.startswith("s3://"):
            raise ValueError("Invalid S3 URI")

        path = uri[5:].lstrip("/")
        if "/" in path:
            bucket, prefix = path.split("/", 1)
            return bucket, prefix.rstrip("/")
        else:
            return path, ""

    @staticmethod
    def _parse_gcs_uri(uri: str) -> Tuple[str, str]:
        """Parse a GCS URI into bucket and prefix."""
        if not uri.startswith("gs://"):
            raise ValueError("Invalid GCS URI")

        path = uri[5:].lstrip("/")
        if "/" in path:
            bucket, prefix = path.split("/", 1)
            return bucket, prefix.rstrip("/")
        else:
            return path, ""

    @staticmethod
    def _parse_azure_uri(uri: str) -> Tuple[str, str]:
        """Parse an Azure Blob Storage URI into container and prefix."""
        if not uri.startswith("azure://"):
            raise ValueError("Invalid Azure Blob Storage URI")

        path = uri[8:].lstrip("/")
        if "/" in path:
            container, prefix = path.split("/", 1)
            return container, prefix.rstrip("/")
        else:
            return path, ""


# Example usage
async def example():
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Create a backup configuration
    config = BackupConfig(
        provider=StorageProvider.LOCAL,
        location="/path/to/backups",
        retention_days=30,
        max_backups=10,
        schedule="0 0 * * *",  # Daily at midnight
        rpo=RecoveryPointObjective.DAILY,
        rto=RecoveryTimeObjective.HOURLY,
    )

    # Create a disaster recovery manager
    drm = DisasterRecoveryManager(config, logger)

    # Start scheduled backups
    await drm.schedule_backups()

    # Create a manual backup
    recovery_point = await drm.create_backup(BackupType.FULL)
    if recovery_point:
        print(f"Created backup: {recovery_point.id}")

    # List recovery points
    points = await drm.list_recovery_points()
    print(f"Found {len(points)} recovery points")

    # Restore from a recovery point
    if points:
        success = await drm.restore_backup(points[0].id)
        print(f"Restore {'succeeded' if success else 'failed'}")

    # Clean up
    await drm.close()


if __name__ == "__main__":
    import asyncio

    asyncio.run(example())
