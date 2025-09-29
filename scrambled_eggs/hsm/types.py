"""
HSM Types and Interfaces

This module contains common types and interfaces used by the HSM module.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class HSMType(Enum):
    """Supported HSM types."""

    CLOUD_KMS = auto()
    PKCS11 = auto()
    TPM = auto()
    SMART_CARD = auto()
    SOFT_HSM = auto()


class KeyType(Enum):
    """Supported key types."""

    AES = auto()
    RSA = auto()
    EC = auto()
    ED25519 = auto()
    X25519 = auto()
    KYBER = auto()
    DILITHIUM = auto()
    SPHINCS_PLUS = auto()


class KeyUsage(Enum):
    """Key usage flags."""

    ENCRYPT = auto()
    DECRYPT = auto()
    SIGN = auto()
    VERIFY = auto()
    WRAP = auto()
    UNWRAP = auto()
    DERIVE = auto()
    KEY_AGREEMENT = auto()


@dataclass
class HSMKey:
    """Represents a key stored in an HSM."""

    key_id: str
    key_type: KeyType
    key_size: int
    algorithm: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    public_key: Optional[bytes] = None
    allowed_operations: List[KeyUsage] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    compliance_info: Dict[str, Any] = field(default_factory=dict)


class HSMInterface(ABC):
    """
    Abstract base class for HSM implementations.

    This provides a unified interface for all HSM operations, with specific
    implementations for different HSM types.
    """

    def __init__(self, hsm_type: "HSMType", config: Dict[str, Any] = None):
        """
        Initialize the HSM interface.

        Args:
            hsm_type: The type of HSM to use
            config: Configuration dictionary for the HSM
        """
        self.hsm_type = hsm_type
        self.config = config or {}
        self.logger = logging.getLogger(f"scrambled_eggs.hsm.{hsm_type.name.lower()}")
        self.initialized = False
        self._session = None

        # Register compliance modules
        from .compliance import FIPS140_3, CommonCriteria, ComplianceManager, SecurityAudit

        self.compliance = ComplianceManager()
        self.compliance.register_module(FIPS140_3())
        self.compliance.register_module(CommonCriteria())
        self.compliance.register_module(SecurityAudit())

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the HSM connection."""
        pass

    @abstractmethod
    def connect(self):
        """Connect to the HSM."""
        pass

    @abstractmethod
    def disconnect(self):
        """Disconnect from the HSM."""
        pass
