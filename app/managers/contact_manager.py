"""
Contact manager for Scrambled Eggs application.
"""
import logging
import json
import hashlib
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any, AsyncGenerator
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import qrcode
from qrcode.image.svg import SvgImage
from pyotp import TOTP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature

from app.core.config import get_config
from app.crypto.scrambled_eggs_encryption import ScrambledEggsEncryption

logger = logging.getLogger(__name__)

@dataclass
class ContactVerification:
    """Contact verification information."""
    verified: bool = False
    verification_level: str = "none"  # 'none', 'fingerprint', 'verified', 'trusted'
    verification_method: Optional[str] = None  # 'qr_code', 'manual', 'trusted_intro'
    verification_date: Optional[datetime] = None
    verification_notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'verified': self.verified,
            'verification_level': self.verification_level,
            'verification_method': self.verification_method,
            'verification_date': self.verification_date.isoformat() if self.verification_date else None,
            'verification_notes': self.verification_notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContactVerification':
        """Create from dictionary."""
        return cls(
            verified=data.get('verified', False),
            verification_level=data.get('verification_level', 'none'),
            verification_method=data.get('verification_method'),
            verification_date=datetime.fromisoformat(data['verification_date']) if data.get('verification_date') else None,
            verification_notes=data.get('verification_notes')
        )

@dataclass
class Contact:
    """Contact information."""
    contact_id: str
    name: str
    public_key: bytes
    last_seen: Optional[datetime] = None
    last_online: Optional[datetime] = None
    status: str = "offline"  # 'online', 'offline', 'away', 'busy', 'invisible'
    avatar_path: Optional[str] = None
    is_favorite: bool = False
    groups: List[str] = field(default_factory=list)
    verification: ContactVerification = field(default_factory=ContactVerification)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert contact to dictionary."""
        return {
            'contact_id': self.contact_id,
            'name': self.name,
            'public_key': self.public_key.hex() if self.public_key else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'last_online': self.last_online.isoformat() if self.last_online else None,
            'status': self.status,
            'avatar_path': self.avatar_path,
            'is_favorite': self.is_favorite,
            'groups': self.groups,
            'verification': self.verification.to_dict(),
            'custom_fields': self.custom_fields,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Contact':
        """Create contact from dictionary."""
        return cls(
            contact_id=data['contact_id'],
            name=data['name'],
            public_key=bytes.fromhex(data['public_key']) if data.get('public_key') else None,
            last_seen=datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None,
            last_online=datetime.fromisoformat(data['last_online']) if data.get('last_online') else None,
            status=data.get('status', 'offline'),
            avatar_path=data.get('avatar_path'),
            is_favorite=data.get('is_favorite', False),
            groups=data.get('groups', []),
            verification=ContactVerification.from_dict(data.get('verification', {})),
            custom_fields=data.get('custom_fields', {}),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.now(timezone.utc)
        )
    
    def update_status(self, status: str):
        """Update contact status and timestamps."""
        now = datetime.now(timezone.utc)
        self.status = status
        self.updated_at = now
        
        if status == 'online':
            self.last_online = now
        
        if status in ['offline', 'invisible']:
            self.last_seen = now
    
    def get_fingerprint(self) -> str:
        """Get a human-readable fingerprint of the public key."""
        if not self.public_key:
            return "No public key"
        
        # Calculate SHA-256 hash of the public key
        sha256 = hashlib.sha256(self.public_key).hexdigest()
        
        # Format as groups of 4 characters for better readability
        return ' '.join(sha256[i:i+4] for i in range(0, len(sha256), 4)).upper()
    
    def get_short_fingerprint(self) -> str:
        """Get a shortened version of the fingerprint."""
        if not self.public_key:
            return "No public key"
        
        # Get the full fingerprint and take first and last 8 characters
        full_fp = self.get_fingerprint().replace(' ', '')
        return f"{full_fp[:8]}...{full_fp[-8:]}"
    
    def generate_qr_code(self, output_path: Optional[Path] = None) -> str:
        """Generate a QR code for contact verification.
        
        Args:
            output_path: Optional path to save the QR code image.
            
        Returns:
            The contact data as a string that can be used to restore the contact.
        """
        if not self.public_key:
            raise ValueError("Contact has no public key")
        
        # Prepare contact data
        contact_data = {
            'version': 1,
            'contact_id': self.contact_id,
            'name': self.name,
            'public_key': self.public_key.hex(),
            'fingerprint': self.get_fingerprint().replace(' ', '')
        }
        
        # Convert to JSON and encode as base64
        import base64
        json_data = json.dumps(contact_data).encode('utf-8')
        encoded_data = base64.urlsafe_b64encode(json_data).decode('ascii')
        
        # Create a QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # Add data to QR code
        qr.add_data(encoded_data)
        qr.make(fit=True)
        
        # Generate the QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to file if path is provided
        if output_path:
            img.save(str(output_path))
        
        # Return the encoded data for programmatic use
        return f"scrambledeggs:contact?data={encoded_data}"
    
    @classmethod
    def from_qr_code(cls, qr_data: str) -> 'Contact':
        """Create a contact from QR code data."""
        import base64
        import json
        
        # Remove the URL scheme if present
        if qr_data.startswith('scrambledeggs:contact?data='):
            qr_data = qr_data.split('=', 1)[1]
        
        try:
            # Decode the base64 data
            json_data = base64.urlsafe_b64decode(qr_data).decode('utf-8')
            contact_data = json.loads(json_data)
            
            # Validate the data
            if 'version' not in contact_data or contact_data['version'] != 1:
                raise ValueError("Unsupported QR code version")
            
            if not all(k in contact_data for k in ['contact_id', 'name', 'public_key', 'fingerprint']):
                raise ValueError("Invalid contact data in QR code")
            
            # Create a new contact
            contact = cls(
                contact_id=contact_data['contact_id'],
                name=contact_data['name'],
                public_key=bytes.fromhex(contact_data['public_key'])
            )
            
            # Verify the fingerprint matches
            if contact.get_fingerprint().replace(' ', '') != contact_data['fingerprint']:
                raise ValueError("Fingerprint verification failed")
            
            return contact
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to parse QR code data: {e}")
            raise ValueError("Invalid QR code data") from e


class ContactManager:
    """Manages contacts and contact-related operations."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the contact manager."""
        self.config = get_config()
        
        # Set up data directory
        if data_dir is None:
            data_dir = Path(self.config.storage.data_dir) / "contacts"
        
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache of contacts
        self._contacts: Dict[str, Contact] = {}
        self._contacts_by_fingerprint: Dict[str, Contact] = {}
        self._groups: Set[str] = set()
        
        # Load contacts from disk
        self.load_contacts()
    
    def load_contacts(self) -> bool:
        """Load contacts from the data directory."""
        try:
            contacts_file = self.data_dir / "contacts.json"
            
            if not contacts_file.exists():
                return False
            
            with open(contacts_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Clear existing contacts
                self._contacts.clear()
                self._contacts_by_fingerprint.clear()
                self._groups.clear()
                
                # Load contacts
                for contact_data in data.get('contacts', []):
                    try:
                        contact = Contact.from_dict(contact_data)
                        self._add_contact_to_cache(contact)
                    except Exception as e:
                        logger.error(f"Failed to load contact: {e}")
                
                # Load groups
                self._groups = set(data.get('groups', []))
                
            logger.info(f"Loaded {len(self._contacts)} contacts and {len(self._groups)} groups")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load contacts: {e}")
            return False
    
    def save_contacts(self) -> bool:
        """Save contacts to the data directory."""
        try:
            contacts_file = self.data_dir / "contacts.json"
            
            # Prepare data for serialization
            data = {
                'version': 1,
                'contacts': [contact.to_dict() for contact in self._contacts.values()],
                'groups': list(self._groups)
            }
            
            # Write to file atomically
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(self.data_dir), delete=False) as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                temp_path = Path(f.name)
            
            # On Windows, we need to remove the destination file first
            if contacts_file.exists():
                contacts_file.unlink()
            
            # Rename the temporary file
            temp_path.rename(contacts_file)
            
            logger.info(f"Saved {len(self._contacts)} contacts and {len(self._groups)} groups")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save contacts: {e}")
            return False
    
    def _add_contact_to_cache(self, contact: Contact):
        """Add a contact to the in-memory cache."""
        self._contacts[contact.contact_id] = contact
        
        # Index by fingerprint if public key is available
        if contact.public_key:
            fingerprint = contact.get_fingerprint().replace(' ', '')
            self._contacts_by_fingerprint[fingerprint] = contact
        
        # Update groups
        for group in contact.groups:
            self._groups.add(group)
    
    def add_contact(self, contact: Contact) -> bool:
        """Add a new contact."""
        if contact.contact_id in self._contacts:
            logger.warning(f"Contact with ID {contact.contact_id} already exists")
            return False
        
        # Add to cache
        self._add_contact_to_cache(contact)
        
        # Save to disk
        return self.save_contacts()
    
    def update_contact(self, contact: Contact) -> bool:
        """Update an existing contact."""
        if contact.contact_id not in self._contacts:
            logger.warning(f"Contact with ID {contact.contact_id} not found")
            return False
        
        # Remove old fingerprint from index if public key changed
        old_contact = self._contacts[contact.contact_id]
        if old_contact.public_key and old_contact.public_key != contact.public_key:
            old_fingerprint = old_contact.get_fingerprint().replace(' ', '')
            if old_fingerprint in self._contacts_by_fingerprint:
                del self._contacts_by_fingerprint[old_fingerprint]
        
        # Update the contact
        contact.updated_at = datetime.now(timezone.utc)
        self._contacts[contact.contact_id] = contact
        
        # Update fingerprint index if needed
        if contact.public_key:
            fingerprint = contact.get_fingerprint().replace(' ', '')
            self._contacts_by_fingerprint[fingerprint] = contact
        
        # Save to disk
        return self.save_contacts()
    
    def delete_contact(self, contact_id: str) -> bool:
        """Delete a contact."""
        if contact_id not in self._contacts:
            logger.warning(f"Contact with ID {contact_id} not found")
            return False
        
        # Remove from fingerprint index
        contact = self._contacts[contact_id]
        if contact.public_key:
            fingerprint = contact.get_fingerprint().replace(' ', '')
            if fingerprint in self._contacts_by_fingerprint:
                del self._contacts_by_fingerprint[fingerprint]
        
        # Remove from contacts
        del self._contacts[contact_id]
        
        # Save to disk
        return self.save_contacts()
    
    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        return self._contacts.get(contact_id)
    
    def get_contact_by_fingerprint(self, fingerprint: str) -> Optional[Contact]:
        """Get a contact by fingerprint."""
        # Remove any spaces from the fingerprint for matching
        fingerprint = fingerprint.replace(' ', '')
        return self._contacts_by_fingerprint.get(fingerprint)
    
    def get_contacts(self, group: Optional[str] = None, favorites_only: bool = False) -> List[Contact]:
        """Get all contacts, optionally filtered by group and/or favorites."""
        contacts = list(self._contacts.values())
        
        if group:
            contacts = [c for c in contacts if group in c.groups]
        
        if favorites_only:
            contacts = [c for c in contacts if c.is_favorite]
        
        # Sort by name, then by ID for consistency
        return sorted(contacts, key=lambda c: (c.name.lower(), c.contact_id))
    
    def get_groups(self) -> List[str]:
        """Get all contact groups."""
        return sorted(self._groups)
    
    def create_group(self, group_name: str) -> bool:
        """Create a new contact group."""
        if not group_name or not group_name.strip():
            return False
        
        if group_name in self._groups:
            return True  # Group already exists
        
        self._groups.add(group_name)
        return self.save_contacts()
    
    def delete_group(self, group_name: str, reassign_to: Optional[str] = None) -> bool:
        """Delete a contact group."""
        if group_name not in self._groups:
            return True  # Group doesn't exist
        
        # Remove the group from all contacts
        for contact in self._contacts.values():
            if group_name in contact.groups:
                contact.groups.remove(group_name)
                
                # Reassign to another group if specified
                if reassign_to and reassign_to != group_name and reassign_to in self._groups:
                    contact.groups.append(reassign_to)
                
                contact.updated_at = datetime.now(timezone.utc)
        
        # Remove the group
        self._groups.remove(group_name)
        
        return self.save_contacts()
    
    def rename_group(self, old_name: str, new_name: str) -> bool:
        """Rename a contact group."""
        if old_name not in self._groups:
            return False
        
        if new_name in self._groups and new_name != old_name:
            # Merge groups
            return self.delete_group(old_name, reassign_to=new_name)
        
        # Update the group name in all contacts
        for contact in self._contacts.values():
            if old_name in contact.groups:
                contact.groups.remove(old_name)
                contact.groups.append(new_name)
                contact.updated_at = datetime.now(timezone.utc)
        
        # Update the groups set
        self._groups.remove(old_name)
        self._groups.add(new_name)
        
        return self.save_contacts()
    
    def verify_contact(self, contact_id: str, method: str = "manual", notes: str = "") -> bool:
        """Mark a contact as verified."""
        contact = self.get_contact(contact_id)
        if not contact:
            return False
        
        contact.verification.verified = True
        contact.verification.verification_level = "verified"
        contact.verification.verification_method = method
        contact.verification.verification_date = datetime.now(timezone.utc)
        contact.verification.verification_notes = notes
        
        contact.updated_at = datetime.now(timezone.utc)
        
        return self.update_contact(contact)
    
    def unverify_contact(self, contact_id: str) -> bool:
        """Remove verification from a contact."""
        contact = self.get_contact(contact_id)
        if not contact:
            return False
        
        contact.verification = ContactVerification()
        contact.updated_at = datetime.now(timezone.utc)
        
        return self.update_contact(contact)
    
    def import_contacts(self, file_path: Path, merge: bool = True) -> Tuple[int, int]:
        """Import contacts from a file.
        
        Args:
            file_path: Path to the import file.
            merge: If True, merge with existing contacts. If False, replace them.
            
        Returns:
            A tuple of (imported_count, error_count)
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Import file not found: {file_path}")
        
        imported = 0
        errors = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Clear existing contacts if not merging
                if not merge:
                    self._contacts.clear()
                    self._contacts_by_fingerprint.clear()
                    self._groups.clear()
                
                # Import contacts
                for contact_data in data.get('contacts', []):
                    try:
                        contact = Contact.from_dict(contact_data)
                        
                        # Skip if contact with same ID already exists
                        if contact.contact_id in self._contacts:
                            if merge:
                                continue
                            else:
                                self.delete_contact(contact.contact_id)
                        
                        self._add_contact_to_cache(contact)
                        imported += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to import contact: {e}")
                        errors += 1
                
                # Import groups
                for group in data.get('groups', []):
                    self._groups.add(group)
                
                # Save the imported contacts
                self.save_contacts()
                
                return imported, errors
                
        except Exception as e:
            logger.error(f"Failed to import contacts: {e}")
            raise
    
    def export_contacts(self, file_path: Path) -> bool:
        """Export contacts to a file."""
        try:
            # Prepare data for export
            data = {
                'version': 1,
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'contacts': [contact.to_dict() for contact in self._contacts.values()],
                'groups': list(self._groups)
            }
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to export contacts: {e}")
            return False
    
    def search_contacts(self, query: str) -> List[Contact]:
        """Search contacts by name, ID, or other attributes."""
        if not query:
            return []
        
        query = query.lower()
        results = []
        
        for contact in self._contacts.values():
            # Search in name
            if query in contact.name.lower():
                results.append(contact)
                continue
            
            # Search in contact ID
            if query in contact.contact_id.lower():
                results.append(contact)
                continue
            
            # Search in groups
            if any(query in group.lower() for group in contact.groups):
                results.append(contact)
                continue
            
            # Search in custom fields
            for key, value in contact.custom_fields.items():
                if isinstance(value, str) and query in value.lower():
                    results.append(contact)
                    break
                elif isinstance(value, (list, tuple)):
                    if any(isinstance(v, str) and query in v.lower() for v in value):
                        results.append(contact)
                        break
        
        return results


def generate_contact_id() -> str:
    """Generate a new contact ID."""
    import uuid
    return str(uuid.uuid4())


def generate_key_pair() -> Tuple[bytes, bytes]:
    """Generate a new RSA key pair.
    
    Returns:
        A tuple of (private_key, public_key) in PEM format
    """
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    # Get the public key
    public_key = private_key.public_key()
    
    # Serialize the keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem
