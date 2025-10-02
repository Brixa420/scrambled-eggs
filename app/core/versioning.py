"""
Versioning system for Scrambled Eggs.

This module provides a comprehensive versioning system that supports:
- Semantic Versioning (SemVer 2.0.0)
- Version constraints and requirements
- Version comparison and sorting
- Dependency resolution
- Version range parsing and matching
"""

import re
import warnings
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import total_ordering
from typing import (
    Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, TypeVar, Union, cast
)

# Type variable for version types
V = TypeVar('V', bound='Version')

class VersionError(ValueError):
    """Base exception for version-related errors."""
    pass

class VersionPart(Enum):
    """Parts of a version number."""
    MAJOR = auto()
    MINOR = auto()
    PATCH = auto()
    PRERELEASE = auto()
    BUILD = auto()

class VersionPreReleaseType(Enum):
    """Types of pre-release versions."""
    ALPHA = 'alpha'
    BETA = 'beta'
    RC = 'rc'
    DEV = 'dev'
    SNAPSHOT = 'snapshot'

@total_ordering
@dataclass(frozen=True)
class Version:
    """A semantic version number (SemVer 2.0.0)."""
    
    major: int = 0
    minor: int = 0
    patch: int = 0
    prerelease: Optional[Tuple[Union[int, str], ...]] = None
    build: Optional[Tuple[Union[int, str], ...]] = None
    
    # Regular expressions for parsing version strings
    _VERSION_PATTERN = re.compile(
        r'^'
        r'(?P<major>0|[1-9]\d*)\.'
        r'(?P<minor>0|[1-9]\d*)\.'
        r'(?P<patch>0|[1-9]\d*)'
        r'(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?'
        r'(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?'
        r'$'
    )
    
    _PRERELEASE_PATTERN = re.compile(
        r'^(?P<type>[a-zA-Z]+)(?P<number>\d*)$'
    )
    
    def __post_init__(self) -> None:
        """Validate the version components."""
        for part in (self.major, self.minor, self.patch):
            if not isinstance(part, int) or part < 0:
                raise VersionError(f"Version components must be non-negative integers: {part}")
        
        if self.prerelease is not None:
            if not isinstance(self.prerelease, tuple):
                raise VersionError("prerelease must be a tuple")
            
            for item in self.prerelease:
                if not (isinstance(item, (int, str)) and str(item)):
                    raise VersionError("prerelease items must be non-empty strings or integers")
                
                if isinstance(item, str) and not item.isalnum() and item != '-':
                    raise VersionError("prerelease strings must be alphanumeric or hyphens")
        
        if self.build is not None:
            if not isinstance(self.build, tuple):
                raise VersionError("build must be a tuple")
            
            for item in self.build:
                if not (isinstance(item, (int, str)) and str(item)):
                    raise VersionError("build items must be non-empty strings or integers")
    
    @classmethod
    def parse(cls: Type[V], version_str: str) -> V:
        """Parse a version string into a Version object.
        
        Args:
            version_str: Version string to parse (e.g., "1.2.3-alpha.1+20230930")
            
        Returns:
            A new Version instance
            
        Raises:
            VersionError: If the version string is invalid
        """
        match = cls._VERSION_PATTERN.match(version_str)
        if not match:
            raise VersionError(f"Invalid version string: {version_str}")
        
        major = int(match.group('major'))
        minor = int(match.group('minor'))
        patch = int(match.group('patch'))
        
        prerelease = None
        if match.group('prerelease'):
            prerelease_parts = []
            for part in match.group('prerelease').split('.'):
                try:
                    prerelease_parts.append(int(part))
                except ValueError:
                    prerelease_parts.append(part)
            prerelease = tuple(prerelease_parts)
        
        build = None
        if match.group('build'):
            build_parts = []
            for part in match.group('build').split('.'):
                try:
                    build_parts.append(int(part))
                except ValueError:
                    build_parts.append(part)
            build = tuple(build_parts)
        
        return cls(major, minor, patch, prerelease, build)
    
    @classmethod
    def coerce(cls: Type[V], version: Union[str, 'Version', Tuple[int, int, int]]) -> V:
        """Coerce a value to a Version object."""
        if isinstance(version, Version):
            return version
        elif isinstance(version, str):
            return cls.parse(version)
        elif isinstance(version, (tuple, list)) and len(version) >= 3:
            return cls(*version[:3])
        else:
            raise VersionError(f"Cannot coerce {version!r} to a Version")
    
    @property
    def is_prerelease(self) -> bool:
        """Check if this is a pre-release version."""
        return self.prerelease is not None
    
    @property
    def is_stable(self) -> bool:
        """Check if this is a stable version (not a pre-release)."""
        return not self.is_prerelease
    
    @property
    def prerelease_type(self) -> Optional[VersionPreReleaseType]:
        """Get the type of pre-release (alpha, beta, rc, etc.)."""
        if not self.prerelease or not self.prerelease[0]:
            return None
            
        prerelease_str = str(self.prerelease[0]).lower()
        
        # Check for common pre-release types
        if 'alpha' in prerelease_str:
            return VersionPreReleaseType.ALPHA
        elif 'beta' in prerelease_str:
            return VersionPreReleaseType.BETA
        elif 'rc' in prerelease_str:
            return VersionPreReleaseType.RC
        elif 'dev' in prerelease_str:
            return VersionPreReleaseType.DEV
        elif 'snapshot' in prerelease_str:
            return VersionPreReleaseType.SNAPSHOT
        
        return None
    
    def bump_major(self: V) -> V:
        """Bump the major version and reset minor and patch."""
        return type(self)(self.major + 1, 0, 0)
    
    def bump_minor(self: V) -> V:
        """Bump the minor version and reset patch."""
        return type(self)(self.major, self.minor + 1, 0)
    
    def bump_patch(self: V) -> V:
        """Bump the patch version."""
        return type(self)(self.major, self.minor, self.patch + 1)
    
    def with_prerelease(self: V, prerelease: str) -> V:
        """Create a new version with the given pre-release identifier."""
        prerelease_parts = []
        for part in prerelease.split('.'):
            try:
                prerelease_parts.append(int(part))
            except ValueError:
                prerelease_parts.append(part)
        
        return type(self)(
            self.major,
            self.minor,
            self.patch,
            tuple(prerelease_parts) if prerelease_parts else None,
            self.build
        )
    
    def with_build(self: V, build: str) -> V:
        """Create a new version with the given build metadata."""
        build_parts = []
        for part in build.split('.'):
            try:
                build_parts.append(int(part))
            except ValueError:
                build_parts.append(part)
        
        return type(self)(
            self.major,
            self.minor,
            self.patch,
            self.prerelease,
            tuple(build_parts) if build_parts else None
        )
    
    def to_tuple(self) -> Tuple[int, int, int, Optional[Tuple[Union[int, str], ...]], Optional[Tuple[Union[int, str], ...]]]:
        """Convert the version to a tuple."""
        return (self.major, self.minor, self.patch, self.prerelease, self.build)
    
    def to_short_string(self) -> str:
        """Convert to a short version string (MAJOR.MINOR.PATCH)."""
        return f"{self.major}.{self.minor}.{self.patch}"
    
    def __str__(self) -> str:
        """Convert to a version string."""
        version = self.to_short_string()
        
        if self.prerelease:
            version += '-' + '.'.join(str(part) for part in self.prerelease)
        
        if self.build:
            version += '+' + '.'.join(str(part) for part in self.build)
        
        return version
    
    def __repr__(self) -> str:
        """Return a string representation of the version."""
        return f"Version('{self}')"
    
    def __eq__(self, other: Any) -> bool:
        """Check if this version is equal to another version."""
        if not isinstance(other, Version):
            try:
                other = self.coerce(other)
            except VersionError:
                return NotImplemented
        
        return (
            self.major == other.major and
            self.minor == other.minor and
            self.patch == other.patch and
            self.prerelease == other.prerelease
        )
    
    def __lt__(self, other: Any) -> bool:
        """Check if this version is less than another version."""
        if not isinstance(other, Version):
            try:
                other = self.coerce(other)
            except VersionError:
                return NotImplemented
        
        # Compare major, minor, patch
        self_tuple = (self.major, self.minor, self.patch)
        other_tuple = (other.major, other.minor, other.patch)
        
        if self_tuple < other_tuple:
            return True
        elif self_tuple > other_tuple:
            return False
        
        # Versions are equal up to prerelease
        # A version with a prerelease has lower precedence than a version without one
        if self.prerelease is None:
            return False  # self is a release, other must be a prerelease
        elif other.prerelease is None:
            return True  # other is a release, self is a prerelease
        
        # Both have prereleases, compare them
        return self._compare_prerelease(self.prerelease, other.prerelease) < 0
    
    @staticmethod
    def _compare_prerelease(a: Tuple[Union[int, str], ...], b: Tuple[Union[int, str], ...]) -> int:
        """Compare two prerelease tuples."""
        for i in range(max(len(a), len(b))):
            if i >= len(a):
                return -1  # a is shorter
            if i >= len(b):
                return 1   # b is shorter
            
            a_part = a[i]
            b_part = b[i]
            
            # Numeric parts have lower precedence than string parts
            if isinstance(a_part, int) and isinstance(b_part, str):
                return -1
            elif isinstance(a_part, str) and isinstance(b_part, int):
                return 1
            
            # Compare parts
            if a_part < b_part:
                return -1
            elif a_part > b_part:
                return 1
        
        return 0  # Equal
    
    def satisfies(self, constraint: 'VersionConstraint') -> bool:
        """Check if this version satisfies the given constraint."""
        return constraint.allows(self)
    
    def is_compatible(self, other: 'Version') -> bool:
        """Check if this version is compatible with another version.
        
        Two versions are compatible if they have the same major version and
        this version is greater than or equal to the other version.
        """
        if not isinstance(other, Version):
            try:
                other = self.coerce(other)
            except VersionError:
                return False
        
        return self.major == other.major and self >= other


class VersionConstraint:
    """A version constraint that can be used to match versions."""
    
    def __init__(self, constraint: str):
        """Initialize a version constraint.
        
        Args:
            constraint: A version constraint string (e.g., "^1.2.3", "~1.0", ">=1.0.0 <2.0.0")
        """
        self.original = constraint.strip()
        self.constraints = self._parse_constraint(constraint)
    
    def _parse_constraint(self, constraint: str) -> List[Tuple[str, Version]]:
        """Parse a version constraint string."""
        if not constraint or constraint == "*":
            return []
        
        # Handle multiple constraints (comma-separated)
        constraints = []
        for part in constraint.split(','):
            part = part.strip()
            if not part:
                continue
                
            # Parse the operator and version
            match = re.match(r'^(?P<op>[=<>~^!]*)\s*(?P<version>.+)$', part)
            if not match:
                raise VersionError(f"Invalid version constraint: {part}")
            
            op = match.group('op')
            version_str = match.group('version')
            
            # Handle special cases
            if op == '~':
                # Tilde range: ~1.2.3 means >=1.2.3 <1.3.0
                version = Version.parse(version_str)
                next_minor = Version(version.major, version.minor + 1, 0)
                return [
                    ('>=', version),
                    ('<', next_minor)
                ]
            elif op == '^':
                # Caret range: ^1.2.3 means >=1.2.3 <2.0.0
                version = Version.parse(version_str)
                next_major = Version(version.major + 1, 0, 0)
                return [
                    ('>=', version),
                    ('<', next_major)
                ]
            elif op.startswith('!='):
                # Not equal: !=1.2.3
                version = Version.parse(version_str)
                constraints.append(('!=', version))
            else:
                # Standard comparison operators: =, ==, >, >=, <, <=
                if not op or op == '=' or op == '==':
                    op = '=='
                    version = Version.parse(version_str)
                else:
                    version = Version.parse(version_str[1:]) if version_str.startswith('=') else Version.parse(version_str)
                
                constraints.append((op, version))
        
        return constraints
    
    def allows(self, version: Union[Version, str]) -> bool:
        """Check if the given version satisfies this constraint."""
        if not self.constraints:
            return True
        
        if not isinstance(version, Version):
            version = Version.parse(version)
        
        for op, constraint_version in self.constraints:
            if op == '==':
                if version != constraint_version:
                    return False
            elif op == '!=':
                if version == constraint_version:
                    return False
            elif op == '>':
                if not (version > constraint_version):
                    return False
            elif op == '>=':
                if not (version >= constraint_version):
                    return False
            elif op == '<':
                if not (version < constraint_version):
                    return False
            elif op == '<=':
                if not (version <= constraint_version):
                    return False
        
        return True
    
    def __str__(self) -> str:
        """Convert the constraint back to a string."""
        if not self.constraints:
            return "*"
        
        return ", ".join(f"{op}{version}" for op, version in self.constraints)
    
    def __repr__(self) -> str:
        """Return a string representation of the constraint."""
        return f"VersionConstraint('{self}')"
    
    def __eq__(self, other: Any) -> bool:
        """Check if two constraints are equal."""
        if not isinstance(other, VersionConstraint):
            return False
        
        return str(self) == str(other)


def compare_versions(v1: Union[Version, str], op: str, v2: Union[Version, str]) -> bool:
    """Compare two versions using the specified operator.
    
    Args:
        v1: First version (Version or string)
        op: Comparison operator (==, !=, <, <=, >, >=)
        v2: Second version (Version or string)
        
    Returns:
        bool: True if the comparison is true, False otherwise
        
    Raises:
        VersionError: If the operator is invalid
    """
    if not isinstance(v1, Version):
        v1 = Version.parse(v1)
    if not isinstance(v2, Version):
        v2 = Version.parse(v2)
    
    if op == '==':
        return v1 == v2
    elif op == '!=':
        return v1 != v2
    elif op == '<':
        return v1 < v2
    elif op == '<=':
        return v1 <= v2
    elif op == '>':
        return v1 > v2
    elif op == '>=':
        return v1 >= v2
    else:
        raise VersionError(f"Invalid comparison operator: {op}")


def max_satisfying(versions: Iterable[Union[Version, str]], constraint: Union[str, VersionConstraint]) -> Optional[Version]:
    """Find the maximum version that satisfies the given constraint.
    
    Args:
        versions: Iterable of versions (Version objects or strings)
        constraint: Version constraint string or VersionConstraint object
        
    Returns:
        The maximum version that satisfies the constraint, or None if no version matches
    """
    if not isinstance(constraint, VersionConstraint):
        constraint = VersionConstraint(constraint)
    
    max_version = None
    
    for version in versions:
        if not isinstance(version, Version):
            try:
                version = Version.parse(version)
            except VersionError:
                continue
        
        if constraint.allows(version):
            if max_version is None or version > max_version:
                max_version = version
    
    return max_version


def sort_versions(versions: Iterable[Union[Version, str]], reverse: bool = False) -> List[Version]:
    """Sort a list of versions.
    
    Args:
        versions: Iterable of versions (Version objects or strings)
        reverse: If True, sort in descending order
        
    Returns:
        List of Version objects in sorted order
    """
    parsed_versions = []
    
    for version in versions:
        if not isinstance(version, Version):
            try:
                parsed_versions.append(Version.parse(version))
            except VersionError:
                continue
        else:
            parsed_versions.append(version)
    
    return sorted(parsed_versions, reverse=reverse)


def is_stable(version: Union[Version, str]) -> bool:
    """Check if a version is stable (not a pre-release)."""
    if not isinstance(version, Version):
        version = Version.parse(version)
    
    return version.is_stable


def get_latest_stable(versions: Iterable[Union[Version, str]]) -> Optional[Version]:
    """Get the latest stable version from a list of versions."""
    stable_versions = [v for v in versions if is_stable(v)]
    return max(stable_versions) if stable_versions else None
