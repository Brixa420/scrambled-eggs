"""
Antivirus scanning module for file security.
Handles file scanning, quarantine, and threat detection.
"""
import os
import hashlib
import logging
import time
import yara
import magic
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, BinaryIO
from datetime import datetime, timedelta
import shutil
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

logger = logging.getLogger(__name__)

class QuarantineManager:
    """Manages quarantined files and related operations."""
    
    def __init__(self, quarantine_dir: str = "quarantine"):
        """Initialize the quarantine manager.
        
        Args:
            quarantine_dir: Directory to store quarantined files
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(exist_ok=True, parents=True)
        self.metadata_file = self.quarantine_dir / "quarantine_metadata.json"
        self.metadata_lock = threading.Lock()
        self._load_metadata()
    
    def _load_metadata(self) -> None:
        """Load quarantine metadata from file."""
        self.metadata = {}
        if self.metadata_file.exists():
            try:
                with self.metadata_lock:
                    with open(self.metadata_file, 'r') as f:
                        self.metadata = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load quarantine metadata: {e}")
    
    def _save_metadata(self) -> None:
        """Save quarantine metadata to file."""
        with self.metadata_lock:
            try:
                with open(self.metadata_file, 'w') as f:
                    json.dump(self.metadata, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save quarantine metadata: {e}")
    
    def quarantine_file(self, file_path: Path, threat_type: str, original_path: str) -> Optional[Path]:
        """Move a file to quarantine.
        
        Args:
            file_path: Path to the file to quarantine
            threat_type: Type of threat detected
            original_path: Original path of the file
            
        Returns:
            Path to quarantined file if successful, None otherwise
        """
        try:
            if not file_path.exists():
                logger.warning(f"File not found for quarantine: {file_path}")
                return None
                
            # Generate unique quarantine filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_hash = self._calculate_file_hash(file_path)
            quarantined_name = f"{timestamp}_{file_hash[:8]}_{file_path.name}"
            quarantined_path = self.quarantine_dir / quarantined_name
            
            # Move file to quarantine
            shutil.move(str(file_path), str(quarantined_path))
            
            # Update metadata
            self.metadata[str(quarantined_path)] = {
                'original_path': str(original_path),
                'threat_type': threat_type,
                'detection_time': datetime.utcnow().isoformat(),
                'file_hash': file_hash,
                'file_size': os.path.getsize(quarantined_path)
            }
            self._save_metadata()
            
            logger.info(f"Quarantined {file_path} as {quarantined_name}")
            return quarantined_path
            
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return None
    
    def restore_file(self, quarantined_path: Path, target_path: Optional[Path] = None) -> bool:
        """Restore a file from quarantine.
        
        Args:
            quarantined_path: Path to the quarantined file
            target_path: Path to restore the file to (defaults to original path)
            
        Returns:
            True if restoration was successful, False otherwise
        """
        try:
            if not quarantined_path.exists():
                logger.warning(f"Quarantined file not found: {quarantined_path}")
                return False
                
            # Get original path from metadata
            file_meta = self.metadata.get(str(quarantined_path))
            if not file_meta:
                logger.warning(f"No metadata found for {quarantined_path}")
                return False
                
            target = Path(target_path) if target_path else Path(file_meta['original_path'])
            target.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file back to original location
            shutil.move(str(quarantined_path), str(target))
            
            # Update metadata
            del self.metadata[str(quarantined_path)]
            self._save_metadata()
            
            logger.info(f"Restored {quarantined_path} to {target}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore {quarantined_path}: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash for identification."""
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()


class FileReputationSystem:
    """Manages file reputation based on hashes and threat intelligence."""
    
    def __init__(self, reputation_db: str = "file_reputation.db"):
        """Initialize the reputation system.
        
        Args:
            reputation_db: Path to the reputation database file
        """
        self.reputation_db = Path(reputation_db)
        self.reputation_data = {}
        self.reputation_lock = threading.Lock()
        self._load_reputation_db()
    
    def _load_reputation_db(self) -> None:
        """Load reputation data from database."""
        if self.reputation_db.exists():
            try:
                with self.reputation_lock:
                    with open(self.reputation_db, 'r') as f:
                        self.reputation_data = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load reputation database: {e}")
    
    def _save_reputation_db(self) -> None:
        """Save reputation data to database."""
        with self.reputation_lock:
            try:
                with open(self.reputation_db, 'w') as f:
                    json.dump(self.reputation_data, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save reputation database: {e}")
    
    def get_reputation(self, file_hash: str) -> Dict[str, any]:
        """Get reputation information for a file hash."""
        return self.reputation_data.get(file_hash, {"reputation": "unknown", "last_seen": None, "detections": 0})
    
    def update_reputation(self, file_hash: str, is_malicious: bool, threat_name: str = "") -> None:
        """Update reputation for a file hash."""
        with self.reputation_lock:
            if file_hash not in self.reputation_data:
                self.reputation_data[file_hash] = {
                    "reputation": "malicious" if is_malicious else "trusted",
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat(),
                    "detections": 1 if is_malicious else 0,
                    "threats": [threat_name] if is_malicious and threat_name else []
                }
            else:
                entry = self.reputation_data[file_hash]
                entry["last_seen"] = datetime.utcnow().isoformat()
                if is_malicious:
                    entry["reputation"] = "malicious"
                    entry["detections"] = entry.get("detections", 0) + 1
                    if threat_name and threat_name not in entry.get("threats", []):
                        entry.setdefault("threats", []).append(threat_name)
            
            self._save_reputation_db()
    
    def report_file(self, file_path: Path, is_malicious: bool, threat_name: str = "") -> bool:
        """Report a file's reputation.
        
        Args:
            file_path: Path to the file to report
            is_malicious: Whether the file is malicious
            threat_name: Name of the threat if malicious
            
        Returns:
            True if report was successful, False otherwise
        """
        try:
            file_hash = self._calculate_file_hash(file_path)
            self.update_reputation(file_hash, is_malicious, threat_name)
            return True
        except Exception as e:
            logger.error(f"Failed to report file {file_path}: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash for identification."""
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()


class AntivirusScanner:
    """Main antivirus scanner class that handles file scanning and threat detection."""
    
    def __init__(self, 
                 rules_dir: str = "antivirus_rules",
                 quarantine_dir: str = "quarantine",
                 max_workers: int = 4):
        """Initialize the antivirus scanner.
        
        Args:
            rules_dir: Directory containing YARA rules
            quarantine_dir: Directory for quarantined files
            max_workers: Maximum number of worker threads for scanning
        """
        self.rules_dir = Path(rules_dir)
        self.quarantine = QuarantineManager(quarantine_dir)
        self.reputation = FileReputationSystem()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans: Set[str] = set()
        self.scan_lock = threading.Lock()
        
        # Initialize file type detector
        try:
            self.mime = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"Failed to initialize magic: {e}"
            self.mime = None
        
        # Load YARA rules
        self.yara_rules = self._load_yara_rules()
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules from the rules directory."""
        try:
            if not self.rules_dir.exists():
                self.rules_dir.mkdir(parents=True)
                logger.warning(f"Created rules directory at {self.rules_dir}")
                return None
                
            yara_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
            if not yara_files:
                logger.warning(f"No YARA rules found in {self.rules_dir}")
                return None
                
            rules = {}
            for yara_file in yara_files:
                try:
                    rules[str(yara_file)] = str(yara_file)
                except yara.Error as e:
                    logger.error(f"Failed to load YARA rule {yara_file}: {e}")
            
            if not rules:
                return None
                
            return yara.compile(filepaths=rules)
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None
    
    async def scan_file(self, file_path: str) -> Dict[str, any]:
        """Scan a single file for threats.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with scan results
        """
        path = Path(file_path)
        if not path.exists():
            return {
                "file": str(path),
                "scanned": False,
                "error": "File does not exist"
            }
        
        # Check if file is already being scanned
        with self.scan_lock:
            if str(path) in self.active_scans:
                return {
                    "file": str(path),
                    "scanned": False,
                    "error": "Scan already in progress"
                }
            self.active_scans.add(str(path))
        
        try:
            # Check file reputation first
            file_hash = self._calculate_file_hash(path)
            reputation = self.reputation.get_reputation(file_hash)
            
            if reputation.get("reputation") == "trusted":
                return {
                    "file": str(path),
                    "scanned": True,
                    "clean": True,
                    "threats": [],
                    "message": "File is trusted"
                }
            
            # Check file type
            file_type = self._get_file_type(path)
            if not self._is_allowed_file_type(file_type):
                return {
                    "file": str(path),
                    "scanned": True,
                    "clean": False,
                    "threats": ["Disallowed file type"],
                    "file_type": file_type,
                    "action": "blocked"
                }
            
            # Scan for threats
            threats = await self._detect_threats(path)
            is_infected = bool(threats)
            
            # Update reputation
            if is_infected:
                self.reputation.update_reputation(
                    file_hash, 
                    is_malicious=True, 
                    threat_name=threats[0] if threats else "Unknown threat"
                )
                
                # Quarantine the file
                quarantined_path = self.quarantine.quarantine_file(
                    path, 
                    threat_type=threats[0] if threats else "Unknown",
                    original_path=str(path)
                )
                
                action = "quarantined" if quarantined_path else "blocked"
            else:
                # Update with clean status
                self.reputation.update_reputation(file_hash, is_malicious=False)
                action = "scanned"
            
            return {
                "file": str(path),
                "scanned": True,
                "clean": not is_infected,
                "threats": threats,
                "file_type": file_type,
                "action": action,
                "quarantined_path": str(quarantined_path) if is_infected and quarantined_path else None
            }
            
        except Exception as e:
            logger.error(f"Error scanning {path}: {e}")
            return {
                "file": str(path),
                "scanned": False,
                "error": str(e)
            }
            
        finally:
            with self.scan_lock:
                self.active_scans.discard(str(path))
    
    async def _detect_threats(self, file_path: Path) -> List[str]:
        """Detect threats in a file."""
        threats = []
        
        # Check YARA rules if available
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(str(file_path))
                for match in matches:
                    threats.append(f"YARA rule match: {match.rule}")
            except Exception as e:
                logger.error(f"YARA scan failed for {file_path}: {e}")
        
        # Add additional detection methods here
        # For example: signature-based detection, heuristics, etc.
        
        return threats
    
    def _get_file_type(self, file_path: Path) -> str:
        """Get the MIME type of a file."""
        try:
            if self.mime:
                return self.mime.from_file(str(file_path))
            return "application/octet-stream"
        except Exception:
            return "application/octet-stream"
    
    def _is_allowed_file_type(self, mime_type: str) -> bool:
        """Check if a file type is allowed."""
        # Define allowed MIME types
        allowed_types = {
            # Text
            'text/plain',
            'text/html',
            'text/css',
            'text/csv',
            'application/json',
            'application/xml',
            'application/x-yaml',
            
            # Documents
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            
            # Images
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/svg+xml',
            'image/webp',
            
            # Archives
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/x-tar',
            'application/gzip',
            'application/x-bzip2',
            
            # Audio/Video
            'audio/mpeg',
            'audio/wav',
            'video/mp4',
            'video/webm',
            'video/quicktime',
            
            # Code
            'application/javascript',
            'application/x-python-code',
            'text/x-python',
            'text/x-c',
            'text/x-c++',
            'text/x-java',
            'text/x-php',
            'text/x-ruby',
            'text/x-shellscript',
        }
        
        return mime_type in allowed_types
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash for identification."""
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    async def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, Dict]:
        """Scan all files in a directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            Dictionary mapping file paths to scan results
        """
        results = {}
        path = Path(directory)
        
        if not path.exists() or not path.is_dir():
            return {"error": f"Directory not found: {directory}"}
        
        # Get all files in directory
        files = []
        if recursive:
            files = [f for f in path.rglob('*') if f.is_file()]
        else:
            files = [f for f in path.iterdir() if f.is_file()]
        
        # Scan files in parallel
        scan_tasks = []
        for file_path in files:
            scan_tasks.append(self.scan_file(str(file_path)))
        
        # Wait for all scans to complete
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Process results
        for result in scan_results:
            if isinstance(result, Exception):
                logger.error(f"Error during scan: {result}")
                continue
            results[result["file"]] = result
        
        return results
    
    def report_malicious_file(self, file_path: str, threat_name: str) -> bool:
        """Report a malicious file to the reputation system.
        
        Args:
            file_path: Path to the malicious file
            threat_name: Name of the threat
            
        Returns:
            True if report was successful, False otherwise
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File not found for reporting: {file_path}")
            return False
            
        return self.reputation.report_file(path, is_malicious=True, threat_name=threat_name)


# Example usage
if __name__ == "__main__":
    import asyncio
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python -m brixa.security.antivirus <file_or_directory>")
            return
            
        target = sys.argv[1]
        scanner = AntivirusScanner()
        
        if os.path.isfile(target):
            result = await scanner.scan_file(target)
            print(json.dumps(result, indent=2))
        elif os.path.isdir(target):
            results = await scanner.scan_directory(target)
            print(f"Scanned {len(results)} files")
            
            # Print summary
            clean = sum(1 for r in results.values() if r.get('clean', False))
            infected = sum(1 for r in results.values() if not r.get('clean', True) and r.get('scanned', False))
            errors = sum(1 for r in results.values() if not r.get('scanned', True))
            
            print(f"Clean: {clean}")
            print(f"Infected: {infected}")
            print(f"Errors: {errors}")
            
            # Print infected files
            if infected > 0:
                print("\nInfected files:")
                for path, result in results.items():
                    if not result.get('clean', True) and result.get('scanned', False):
                        print(f"- {path}: {', '.join(result.get('threats', ['Unknown threat']))}")
        else:
            print(f"File or directory not found: {target}")
    
    asyncio.run(main())
