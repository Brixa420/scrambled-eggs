"""
Version management for AI models in the Brixa platform.

This module provides classes for managing model versions, including version status,
metadata, and lifecycle management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, Any, Optional, List, Set, Union
import re
import logging

logger = logging.getLogger(__name__)

# Version string pattern (semantic versioning)
VERSION_PATTERN = re.compile(
    r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
)

class VersionStatus(Enum):
    """Represents the lifecycle status of a model version."""
    DRAFT = auto()        # Initial state, under development
    STAGING = auto()      # Ready for testing in staging
    PRODUCTION = auto()   # Actively serving production traffic
    DEPRECATED = auto()   # Still serving but will be removed soon
    ARCHIVED = auto()     # No longer in use, kept for reference
    
    def can_promote_to(self, target_status: 'VersionStatus') -> bool:
        """Check if a version can be promoted to the target status."""
        promotion_path = {
            VersionStatus.DRAFT: {VersionStatus.STAGING, VersionStatus.ARCHIVED},
            VersionStatus.STAGING: {VersionStatus.PRODUCTION, VersionStatus.ARCHIVED},
            VersionStatus.PRODUCTION: {VersionStatus.DEPRECATED, VersionStatus.ARCHIVED},
            VersionStatus.DEPRECATED: {VersionStatus.ARCHIVED},
            VersionStatus.ARCHIVED: set()
        }
        return target_status in promotion_path[self]

@dataclass
class VersionInfo:
    """Metadata and state information for a specific model version."""
    version: str
    created_at: datetime
    updated_at: datetime
    status: VersionStatus
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_version: Optional[str] = None
    framework: str = ""
    framework_version: str = ""
    tags: Set[str] = field(default_factory=set)
    metrics: Dict[str, float] = field(default_factory=dict)
    storage_path: Optional[str] = None
    
    def __post_init__(self):
        """Initialize and validate version info."""
        if self.metadata is None:
            self.metadata = {}
        if isinstance(self.status, str):
            self.status = VersionStatus[self.status.upper()]
        if not VERSION_PATTERN.match(self.version):
            logger.warning(
                f"Version '{self.version}' does not follow semantic versioning (e.g., 1.0.0)"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'version': self.version,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'status': self.status.name,
            'description': self.description,
            'metadata': self.metadata,
            'parent_version': self.parent_version,
            'framework': self.framework,
            'framework_version': self.framework_version,
            'tags': list(self.tags),
            'metrics': self.metrics,
            'storage_path': self.storage_path
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VersionInfo':
        """Create from a dictionary."""
        data = data.copy()
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        data['status'] = VersionStatus[data['status']]
        data['tags'] = set(data.get('tags', []))
        return cls(**data)

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if isinstance(self.status, str):
            self.status = VersionStatus[self.status.upper()]

class VersionManager:
    """Manages versions of a model, including lifecycle and promotion."""
    
    def __init__(self, model_name: str):
        """Initialize with the name of the model being versioned."""
        self.model_name = model_name
        self.versions: Dict[str, VersionInfo] = {}
        self._production_version: Optional[str] = None

    def create_version(
        self,
        version: str,
        framework: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        parent_version: Optional[str] = None,
        framework_version: str = "",
        tags: Optional[List[str]] = None,
        metrics: Optional[Dict[str, float]] = None,
        storage_path: Optional[str] = None
    ) -> VersionInfo:
        """Create a new version of the model.
        
        Args:
            version: Version string (should follow semantic versioning)
            framework: ML framework used (e.g., 'pytorch', 'tensorflow')
            description: Human-readable description of the version
            metadata: Additional metadata as key-value pairs
            parent_version: Parent version this was derived from
            framework_version: Version of the framework used
            tags: List of tags for categorization
            metrics: Performance metrics for this version
            storage_path: Path to the model artifacts
            
        Returns:
            VersionInfo: The created version information
            
        Raises:
            ValueError: If the version already exists or is invalid
        """
        if version in self.versions:
            raise ValueError(f"Version {version} already exists for model {self.model_name}")
            
        now = datetime.utcnow()
        version_info = VersionInfo(
            version=version,
            created_at=now,
            updated_at=now,
            status=VersionStatus.DRAFT,
            description=description,
            metadata=metadata or {},
            parent_version=parent_version,
            framework=framework,
            framework_version=framework_version,
            tags=set(tags or []),
            metrics=metrics or {},
            storage_path=storage_path
        
        self.versions[version] = version_info
        logger.info(f"Created new version {version} of model {self.model_name}")
        return version_info

    def promote_version(self, version: str, new_status: VersionStatus) -> VersionInfo:
        """Promote a version to a new status.
        
        Args:
            version: Version to promote
            new_status: New status to promote to
            
        Returns:
            VersionInfo: The updated version information
            
        Raises:
            ValueError: If the version doesn't exist or promotion is not allowed
        """
        if version not in self.versions:
            raise ValueError(f"Version {version} does not exist in model {self.model_name}")
            
        return lineage

    def rollback_version(self, version: str, new_version: str) -> Optional[VersionInfo]:
        if version not in self.versions:
            return None

        version_info = self.versions[version]
        return self.create_version(
            version=new_version,
            framework=version_info.framework,
            description=f"Rollback to {version}",
            metadata=version_info.metadata.copy(),
            parent_version=version
        )
