"""
Memory Protection
----------------
Implements secure memory management to protect sensitive data from memory dumps
and other memory analysis attacks.
"""
import os
import sys
import ctypes
import hashlib
import logging
import platform
import threading
import weakref
from typing import Any, Optional, Dict, List, Callable, TypeVar, Generic, Type, Union
from ctypes import c_void_p, c_char_p, c_size_t, c_ubyte, Structure, POINTER

# Type variable for generic memory protection
T = TypeVar('T')

class MemoryProtectionError(Exception):
    """Base exception for memory protection errors."""
    pass

class SecureMemoryAllocationError(MemoryProtectionError):
    """Raised when secure memory allocation fails."""
    pass

class MemoryLockError(MemoryProtectionError):
    """Raised when memory locking operations fail."""
    pass

class SecureBuffer:
    """A secure buffer that protects sensitive data in memory."""
    
    # Platform-specific constants
    if platform.system() == 'Windows':
        # Windows constants
        MEM_COMMIT = 0x00001000
        MEM_RESERVE = 0x00002000
        PAGE_READWRITE = 0x04
        PAGE_READONLY = 0x02
        PAGE_NOACCESS = 0x01
        MEM_RELEASE = 0x8000
        
        # Windows API functions
        _kernel32 = ctypes.windll.kernel32
        _virtual_alloc = _kernel32.VirtualAlloc
        _virtual_free = _kernel32.VirtualFree
        _virtual_protect = _kernel32.VirtualProtect
        _virtual_lock = _kernel32.VirtualLock
        _virtual_unlock = _kernel32.VirtualUnlock
        
        # Try to get RtlSecureZeroMemory, fall back to memset if not available
        try:
            _rtl_secure_zero_memory = _kernel32.RtlSecureZeroMemory
            _rtl_secure_zero_memory.argtypes = [c_void_p, c_size_t]
            _rtl_secure_zero_memory.restype = c_void_p
            _secure_zero_memory = _rtl_secure_zero_memory
        except AttributeError:
            # Fallback implementation using memset
            _memset = ctypes.cdll.msvcrt.memset
            _memset.argtypes = [c_void_p, ctypes.c_int, c_size_t]
            _memset.restype = c_void_p
            
            def _secure_zero_memory(ptr, size):
                return _memset(ptr, 0, size)
        
        _virtual_alloc.argtypes = [c_void_p, c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        _virtual_alloc.restype = c_void_p
        
        _virtual_free.argtypes = [c_void_p, c_size_t, ctypes.c_ulong]
        _virtual_free.restype = bool
        
        _virtual_protect.argtypes = [c_void_p, c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        _virtual_protect.restype = bool
        
        _virtual_lock.argtypes = [c_void_p, c_size_t]
        _virtual_lock.restype = bool
        
        _virtual_unlock.argtypes = [c_void_p, c_size_t]
        _virtual_unlock.restype = bool
        
    else:
        # POSIX constants and functions (Linux, macOS, etc.)
        import mmap
        import fcntl
        
        # POSIX memory protection flags
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_NONE = 0x0
        
        # POSIX memory locking
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        
        # POSIX memory advice
        MADV_DONTDUMP = 16  # Linux specific
        MADV_WIPEONFORK = 18  # Linux specific
        
        # POSIX system calls
        _libc = ctypes.CDLL(None)
        _sysconf = _libc.sysconf
        _sysconf.argtypes = [ctypes.c_int]
        _sysconf.restype = ctypes.c_long
        
        _mlock = _libc.mlock
        _mlock.argtypes = [c_void_p, c_size_t]
        _mlock.restype = ctypes.c_int
        
        _munlock = _libc.munlock
        _munlock.argtypes = [c_void_p, c_size_t]
        _munlock.restype = ctypes.c_int
        
        _mprotect = _libc.mprotect
        _mprotect.argtypes = [c_void_p, c_size_t, ctypes.c_int]
        _mprotect.restype = ctypes.c_int
        
        _memset = _libc.memset
        _memset.argtypes = [c_void_p, ctypes.c_int, c_size_t]
        _memset.restype = c_void_p
        
        _getpagesize = _libc.getpagesize
        _getpagesize.argtypes = []
        _getpagesize.restype = ctypes.c_int
        
        try:
            _madvise = _libc.madvise
            _madvise.argtypes = [c_void_p, c_size_t, ctypes.c_int]
            _madvise.restype = ctypes.c_int
            HAS_MADVISE = True
        except AttributeError:
            HAS_MADVISE = False
    
    def __init__(self, size: int, lock_memory: bool = True, wipe_on_fork: bool = True):
        """Initialize a secure memory buffer.
        
        Args:
            size: Size of the buffer in bytes
            lock_memory: Whether to lock the memory to prevent swapping
            wipe_on_fork: Whether to wipe memory on fork (POSIX only)
        """
        self._size = size
        self._lock_memory = lock_memory
        self._wipe_on_fork = wipe_on_fork
        self._locked = False
        self._address = None
        self._allocated = False
        
        # Allocate the memory
        self._allocate()
        
        # Register cleanup on program exit
        import atexit
        atexit.register(self.free)
        
        # Use weakref.finalize for more reliable cleanup
        self._finalizer = weakref.finalize(self, self._cleanup, self._address, self._size)
    
    def _allocate(self) -> None:
        """Allocate secure memory."""
        try:
            if platform.system() == 'Windows':
                # Allocate memory with PAGE_READWRITE access
                self._address = self._virtual_alloc(
                    None,  # System selects the address
                    self._size,  # Size of allocation
                    self.MEM_COMMIT | self.MEM_RESERVE,  # Allocation type
                    self.PAGE_READWRITE  # Memory protection
                )
                
                if not self._address:
                    raise SecureMemoryAllocationError("Failed to allocate secure memory")
                
                # Lock the memory to prevent swapping
                if self._lock_memory:
                    if not self._virtual_lock(self._address, self._size):
                        self._virtual_free(self._address, 0, self.MEM_RELEASE)
                        raise MemoryLockError("Failed to lock memory")
                    self._locked = True
                
                # Mark as allocated
                self._allocated = True
                
            else:  # POSIX (Linux, macOS, etc.)
                # Get system page size
                page_size = self._getpagesize()
                
                # Calculate aligned size (multiple of page size)
                aligned_size = ((self._size + page_size - 1) // page_size) * page_size
                
                # Allocate memory with mmap
                self._address = ctypes.create_string_buffer(aligned_size)
                
                # Lock the memory to prevent swapping
                if self._lock_memory:
                    if self._mlock(self._address, aligned_size) != 0:
                        raise MemoryLockError("Failed to lock memory")
                    self._locked = True
                
                # Additional protection on Linux
                if platform.system() == 'Linux':
                    # Prevent core dumps from including this memory
                    if HAS_MADVISE:
                        self._madvise(ctypes.addressof(self._address), aligned_size, self.MADV_DONTDUMP)
                    
                    # Wipe memory on fork
                    if self._wipe_on_fork and HAS_MADVISE:
                        self._madvise(ctypes.addressof(self._address), aligned_size, self.MADV_WIPEONFORK)
                
                # Mark as allocated
                self._allocated = True
                
        except Exception as e:
            if self._address and not self._allocated:
                self._cleanup(self._address, self._size)
            raise MemoryProtectionError(f"Failed to allocate secure memory: {e}")
    
    def _zero_memory(self, ptr: int, size: int) -> None:
        """Securely zero out a memory region."""
        if platform.system() == 'Windows':
            self._secure_zero_memory(ptr, size)
        else:
            # On Unix-like systems, use memset through ctypes
            ctypes.memset(ptr, 0, size)
    
    def _cleanup(self, address: int, size: int) -> None:
        """Clean up memory resources."""
        try:
            if platform.system() == 'Windows':
                if self._locked:
                    self._virtual_unlock(address, size)
                    self._locked = False
                
                # Free the memory
                if self._allocated:
                    self._virtual_free(address, 0, self.MEM_RELEASE)
                    self._allocated = False
            else:  # POSIX
                # Overwrite with zeros
                self._memset(address, 0, size)
                
                # Unlock memory if it was locked
                if self._locked:
                    self._munlock(address, size)
                    self._locked = False
                
                # Memory will be freed when the buffer is garbage collected
                
        except Exception as e:
            # Can't raise exceptions in __del__ or finalizer
            import warnings
            warnings.warn(f"Error cleaning up secure memory: {e}")
        finally:
            self._address = None
    
    def write(self, data: bytes) -> None:
        """Write data to the secure buffer."""
        if not self._address or not self._allocated:
            raise MemoryProtectionError("Secure buffer not allocated")
        
        if len(data) > self._size:
            raise ValueError(f"Data size ({len(data)}) exceeds buffer size ({self._size})")
        
        try:
            if platform.system() == 'Windows':
                # Write the data
                ctypes.memmove(self._address, data, len(data))
            else:
                # Write the data to the buffer
                ctypes.memmove(ctypes.addressof(self._address), data, len(data))
        except Exception as e:
            raise MemoryProtectionError(f"Failed to write to secure buffer: {e}")
    
    def read(self, size: Optional[int] = None) -> bytes:
        """Read data from the secure buffer."""
        if not self._address or not self._allocated:
            raise MemoryProtectionError("Secure buffer not allocated")
        
        read_size = min(size, self._size) if size is not None else self._size
        
        try:
            if platform.system() == 'Windows':
                return ctypes.string_at(self._address, read_size)
            else:
                return ctypes.string_at(ctypes.addressof(self._address), read_size)
        except Exception as e:
            raise MemoryProtectionError(f"Failed to read from secure buffer: {e}")
    
    def protect(self, read_only: bool = True) -> None:
        """Change the protection of the memory region."""
        if not self._address or not self._allocated:
            raise MemoryProtectionError("Secure buffer not allocated")
        
        try:
            if platform.system() == 'Windows':
                old_protect = ctypes.c_ulong(0)
                if read_only:
                    protect = self.PAGE_READONLY
                else:
                    protect = self.PAGE_READWRITE
                
                if not self._virtual_protect(self._address, self._size, protect, ctypes.byref(old_protect)):
                    raise MemoryProtectionError("Failed to change memory protection")
            else:
                if read_only:
                    prot = self.PROT_READ
                else:
                    prot = self.PROT_READ | self.PROT_WRITE
                
                if self._mprotect(ctypes.addressof(self._address), self._size, prot) != 0:
                    raise MemoryProtectionError("Failed to change memory protection")
                    
        except Exception as e:
            raise MemoryProtectionError(f"Failed to protect memory: {e}")
    
    def lock(self) -> None:
        """Lock the memory to prevent swapping."""
        if self._locked:
            return
            
        if not self._address or not self._allocated:
            raise MemoryProtectionError("Secure buffer not allocated")
        
        try:
            if platform.system() == 'Windows':
                if not self._virtual_lock(self._address, self._size):
                    raise MemoryLockError("Failed to lock memory")
            else:
                if self._mlock(ctypes.addressof(self._address), self._size) != 0:
                    raise MemoryLockError("Failed to lock memory")
            
            self._locked = True
            
        except Exception as e:
            raise MemoryLockError(f"Failed to lock memory: {e}")
    
    def unlock(self) -> None:
        """Unlock the memory (allow swapping)."""
        if not self._locked:
            return
            
        if not self._address or not self._allocated:
            raise MemoryProtectionError("Secure buffer not allocated")
        
        try:
            if platform.system() == 'Windows':
                if not self._virtual_unlock(self._address, self._size):
                    raise MemoryLockError("Failed to unlock memory")
            else:
                if self._munlock(ctypes.addressof(self._address), self._size) != 0:
                    raise MemoryLockError("Failed to unlock memory")
            
            self._locked = False
            
        except Exception as e:
            raise MemoryLockError(f"Failed to unlock memory: {e}")
    
    def free(self) -> None:
        """Free the secure memory."""
        if not self._allocated:
            return
            
        if self._finalizer is not None:
            self._finalizer()
        
        self._cleanup(self._address, self._size)
        self._allocated = False
        self._address = None
    
    def __del__(self):
        """Destructor to ensure memory is freed."""
        self.free()
    
    @property
    def address(self) -> int:
        """Get the memory address of the buffer."""
        if not self._address:
            raise MemoryProtectionError("Buffer not allocated")
        return self._address if platform.system() == 'Windows' else ctypes.addressof(self._address)
    
    @property
    def size(self) -> int:
        """Get the size of the buffer."""
        return self._size
    
    @property
    def is_locked(self) -> bool:
        """Check if the memory is locked."""
        return self._locked


class SecureString:
    """A string that is stored securely in memory."""
    
    def __init__(self, value: str = "", encoding: str = 'utf-8'):
        """Initialize a secure string.
        
        Args:
            value: The string value to store securely
            encoding: The string encoding to use
        """
        self._encoding = encoding
        self._buffer = None
        self._length = 0
        
        if value:
            self.value = value
    
    @property
    def value(self) -> str:
        """Get the string value."""
        if not self._buffer:
            return ""
            
        try:
            # Read the data from the secure buffer
            data = self._buffer.read(self._length)
            return data.decode(self._encoding)
        except Exception as e:
            raise MemoryProtectionError(f"Failed to read secure string: {e}")
        finally:
            # Always clear the temporary buffer
            if 'data' in locals():
                del data
    
    @value.setter
    def value(self, value: str) -> None:
        """Set the string value."""
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        
        # Convert to bytes
        data = value.encode(self._encoding)
        self._length = len(data)
        
        # Free the old buffer if it exists
        if self._buffer is not None:
            self._buffer.free()
        
        # Allocate a new secure buffer
        self._buffer = SecureBuffer(len(data) + 1)  # +1 for null terminator
        
        try:
            # Write the data to the secure buffer
            self._buffer.write(data + b'\x00')  # Add null terminator
            
            # Make the buffer read-only
            self._buffer.protect(read_only=True)
            
        except Exception as e:
            self._buffer.free()
            self._buffer = None
            self._length = 0
            raise MemoryProtectionError(f"Failed to set secure string: {e}")
    
    def clear(self) -> None:
        """Securely clear the string from memory."""
        if self._buffer is not None:
            self._buffer.free()
            self._buffer = None
        self._length = 0
    
    def __str__(self) -> str:
        """Get the string representation."""
        return self.value
    
    def __repr__(self) -> str:
        """Get the string representation for debugging."""
        return f"<SecureString length={self._length}>"
    
    def __len__(self) -> int:
        """Get the length of the string."""
        return self._length
    
    def __del__(self):
        """Destructor to ensure memory is cleared."""
        self.clear()


class SecureBytes:
    """A bytes-like object that is stored securely in memory."""
    
    def __init__(self, value: bytes = b""):
        """Initialize secure bytes.
        
        Args:
            value: The bytes to store securely
        """
        self._buffer = None
        self._length = 0
        
        if value:
            self.value = value
    
    @property
    def value(self) -> bytes:
        """Get the bytes value."""
        if not self._buffer:
            return b""
            
        try:
            # Read the data from the secure buffer
            return self._buffer.read(self._length)
        except Exception as e:
            raise MemoryProtectionError(f"Failed to read secure bytes: {e}")
    
    @value.setter
    def value(self, value: bytes) -> None:
        """Set the bytes value."""
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("Value must be bytes or bytearray")
        
        self._length = len(value)
        
        # Free the old buffer if it exists
        if self._buffer is not None:
            self._buffer.free()
        
        # Allocate a new secure buffer
        self._buffer = SecureBuffer(self._length)
        
        try:
            # Write the data to the secure buffer
            self._buffer.write(bytes(value))
            
            # Make the buffer read-only
            self._buffer.protect(read_only=True)
            
        except Exception as e:
            self._buffer.free()
            self._buffer = None
            self._length = 0
            raise MemoryProtectionError(f"Failed to set secure bytes: {e}")
    
    def clear(self) -> None:
        """Securely clear the bytes from memory."""
        if self._buffer is not None:
            self._buffer.free()
            self._buffer = None
        self._length = 0
    
    def __bytes__(self) -> bytes:
        """Get the bytes value."""
        return self.value
    
    def __len__(self) -> int:
        """Get the length of the bytes."""
        return self._length
    
    def __getitem__(self, index: int) -> int:
        """Get a byte at the given index."""
        return self.value[index]
    
    def __iter__(self):
        """Iterate over the bytes."""
        return iter(self.value)
    
    def __del__(self):
        """Destructor to ensure memory is cleared."""
        self.clear()


def secure_erase(obj: Any) -> None:
    """Securely erase sensitive data from memory."""
    if isinstance(obj, (SecureString, SecureBytes)):
        obj.clear()
    elif isinstance(obj, (str, bytes, bytearray)):
        # For regular strings and bytes, we can't securely erase them
        # as Python's string interning and memory management might keep copies
        pass
    elif hasattr(obj, '__dict__'):
        # Recursively clear attributes
        for attr_name, attr_value in obj.__dict__.items():
            secure_erase(attr_value)
    elif isinstance(obj, (list, tuple, set)):
        # Recursively clear elements
        for item in obj:
            secure_erase(item)
    elif isinstance(obj, dict):
        # Recursively clear values
        for key, value in obj.items():
            secure_erase(value)


def secure_compare(a: Union[str, bytes, bytearray], 
                  b: Union[str, bytes, bytearray]) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def secure_hash(data: Union[str, bytes], 
               algorithm: str = 'sha256', 
               salt: Optional[bytes] = None) -> bytes:
    """Generate a secure hash of the data with an optional salt."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes or None")
    
    # Use a secure hash function
    hash_func = getattr(hashlib, algorithm, hashlib.sha256)
    
    # Hash the data with the salt
    h = hash_func()
    if salt is not None:
        h.update(salt)
    h.update(data)
    
    return h.digest()


def secure_random_bytes(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes."""
    if not isinstance(length, int) or length < 1:
        raise ValueError("Length must be a positive integer")
    
    return os.urandom(length)


def secure_random_string(length: int = 32, 
                       charset: str = 'abcdefghijklmnopqrstuvwxyz'
                                     'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                     '0123456789!@#$%^&*()-_=+') -> str:
    """Generate a cryptographically secure random string.
    
    Args:
        length: Length of the random string
        charset: Characters to use for the random string
        
    Returns:
        A random string of the specified length
    """
    import random
    rand = random.SystemRandom()
    return ''.join(rand.choice(charset) for _ in range(length))


class MemoryProtector:
    """A class that provides high-level memory protection functionality."""
    
    def __init__(self):
        self._buffers = []
        
    def protect(self, data: Union[bytes, str]) -> 'SecureBuffer':
        """Protect sensitive data in memory.
        
        Args:
            data: The data to protect (bytes or string)
            
        Returns:
            A SecureBuffer containing the protected data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        buffer = SecureBuffer(len(data))
        buffer.write(data)
        self._buffers.append(buffer)
        return buffer
        
    def clear(self) -> None:
        """Securely clear all protected memory."""
        for buffer in self._buffers:
            buffer.free()
        self._buffers.clear()
        
    def __del__(self):
        """Ensure all protected memory is cleared when the object is destroyed."""
        self.clear()
        
    def __enter__(self):
        """Context manager entry."""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure memory is cleared."""
        self.clear()
