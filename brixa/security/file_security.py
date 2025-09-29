"""
File security module for virus scanning and malicious content detection.
"""
import os
import hashlib
import re
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import magic

logger = logging.getLogger(__name__)

class FileSecurity:
    """Handles file security operations including virus scanning and content verification."""
    
    def __init__(self, max_workers: int = 4):
        """Initialize the file security scanner.
        
        Args:
            max_workers: Maximum number of worker threads for scanning
        """
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.file_signatures = self._load_known_signatures()
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        self.scan_cache: Dict[str, Tuple[bool, float]] = {}
        
        # Initialize file type detector
        try:
            self.mime = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"Failed to initialize magic: {e}")
            self.mime = None
    
    def _load_known_signatures(self) -> Dict[bytes, str]:
        """Load known file signatures for verification."""
        return {
            b'\x25\x50\x44\x46': 'pdf',
            b'\x50\x4B\x03\x04': 'zip',
            b'\x52\x61\x72\x21': 'rar',
            b'\x89\x50\x4E\x47': 'png',
            b'\xFF\xD8\xFF': 'jpg',
            b'\x47\x49\x46\x38': 'gif',
            b'\x49\x44\x33': 'mp3',
            b'PK\x03\x04': 'docx'  # Office Open XML
        }
    
    async def scan_file(self, file_path: str) -> Dict[str, any]:
        """Scan a file for potential threats."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Check cache first
        file_hash = self._calculate_file_hash(file_path)
        if file_hash in self.scan_cache:
            is_safe, timestamp = self.scan_cache[file_hash]
            if (time.time() - timestamp) < 86400:  # 24h cache
                return {
                    'safe': is_safe,
                    'cached': True,
                    'threats_found': [] if is_safe else ['Cached threat detected'],
                    'file_type': self._detect_file_type(file_path)
                }
        
        # Perform security checks
        threats = []
        
        # 1. Check file type
        file_type = self._detect_file_type(file_path)
        if not self._is_safe_file_type(file_path):
            threats.append(f"Potentially dangerous file type: {file_type}")
        
        # 2. Check file signature
        if not self._verify_file_signature(file_path):
            threats.append("File signature doesn't match its extension")
        
        # 3. Check for suspicious content
        if self._contains_suspicious_patterns(file_path):
            threats.append("Suspicious patterns detected")
        
        # Update cache
        is_safe = len(threats) == 0
        self.scan_cache[file_hash] = (is_safe, time.time())
        
        return {
            'safe': is_safe,
            'cached': False,
            'threats_found': threats,
            'file_type': file_type,
            'file_size': file_path.stat().st_size,
            'file_hash': file_hash
        }
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using magic numbers."""
        if self.mime:
            try:
                return self.mime.from_file(str(file_path)).split('/')[-1].lower()
            except Exception as e:
                logger.warning(f"Error detecting file type: {e}")
        return file_path.suffix.lower().lstrip('.')
    
    def _is_safe_file_type(self, file_path: Path) -> bool:
        """Check if file type is in the allowed list."""
        safe_extensions = {
            # Documents
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf',
            # Images
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg',
            # Archives
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
            # Media
            'mp3', 'wav', 'mp4', 'avi', 'mov', 'mkv',
            # Other
            'json', 'xml', 'csv'
        }
        return file_path.suffix.lower().lstrip('.') in safe_extensions
    
    def _verify_file_signature(self, file_path: Path) -> bool:
        """Verify file signature matches its extension."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            ext = file_path.suffix.lower().lstrip('.')
            
            for signature, sig_ext in self.file_signatures.items():
                if header.startswith(signature):
                    return sig_ext.lower() == ext
                    
            return True  # No signature for this file type
            
        except Exception as e:
            logger.warning(f"Error verifying signature: {e}")
            return False
    
    def _contains_suspicious_patterns(self, file_path: Path) -> bool:
        """Check for common exploit patterns."""
        suspicious_patterns = [
            b'<script>', b'eval\(', b'document\.cookie',
            b'fromCharCode', b'exec\s*\(', b'system\(',
            b'shell_exec\(', b'passthru\s*\('
        ]
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Check first 8KB
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                        
        except Exception as e:
            logger.warning(f"Error checking for patterns: {e}")
            
        return False
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash for identification."""
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return ""
    
    async def quarantine_file(self, file_path: Path) -> bool:
        """Move a suspicious file to quarantine."""
        try:
            if not file_path.exists():
                return False
                
            quarantine_path = self.quarantine_dir / f"quarantined_{file_path.name}"
            file_path.rename(quarantine_path)
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return False
