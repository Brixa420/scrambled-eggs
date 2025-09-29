"""
Biometric Authentication Module
Handles Face ID, Touch ID, and other biometric authentication methods.
"""
import platform
import logging
from typing import Optional, Callable, Any
import asyncio

logger = logging.getLogger(__name__)

class BiometricAuth:
    """Handles biometric authentication across different platforms."""
    
    def __init__(self):
        self.system = platform.system()
        self.available = self._check_biometric_availability()
        
    def _check_biometric_availability(self) -> bool:
        """Check if biometric authentication is available on the current system."""
        try:
            if self.system == "Darwin":  # macOS/iOS
                import LocalAuthentication
                context = LocalAuthentication.LAContext()
                return context.canEvaluatePolicy_error_(1, None)[0]  # kLAPolicyDeviceOwnerAuthenticationWithBiometrics
            elif self.system == "Windows":
                import win32security
                # Windows Hello is available on Windows 10+
                return hasattr(win32security, 'CredUIPromptForWindowsCredentials')
            elif self.system == "Linux":
                # Check for fingerprint reader on Linux
                import os
                return os.path.exists("/etc/pam.d/fingerprint-auth")
            return False
        except ImportError:
            logger.warning("Required biometric authentication libraries not found")
            return False
        except Exception as e:
            logger.error(f"Error checking biometric availability: {e}")
            return False
    
    async def authenticate(self, reason: str = "Authenticate to access secure content") -> bool:
        """
        Authenticate using biometrics.
        
        Args:
            reason: The reason for authentication to show to the user.
            
        Returns:
            bool: True if authentication was successful, False otherwise.
        """
        if not self.available:
            logger.warning("Biometric authentication not available on this device")
            return False
            
        try:
            if self.system == "Darwin":
                return await self._authenticate_darwin(reason)
            elif self.system == "Windows":
                return await self._authenticate_windows(reason)
            elif self.system == "Linux":
                return await self._authenticate_linux(reason)
            return False
        except Exception as e:
            logger.error(f"Biometric authentication failed: {e}")
            return False
    
    async def _authenticate_darwin(self, reason: str) -> bool:
        """Authenticate on macOS/iOS using LocalAuthentication framework."""
        from LocalAuthentication import LAContext, LAError
        from Foundation import NSObject, NSRunLoop, NSDefaultRunLoopMode
        
        class AuthDelegate(NSObject):
            def __init__(self):
                self.done = False
                self.success = False
                self.loop = asyncio.get_event_loop()
                
            def callback(self, success: bool, error: Any) -> None:
                self.success = success
                if error:
                    logger.error(f"Biometric auth error: {error}")
                self.done = True
                self.loop.call_soon_threadsafe(lambda: None)
        
        context = LAContext.LAContext()
        delegate = AuthDelegate()
        
        # Use the completion handler style API
        context.evaluatePolicy_localizedReason_reply_(
            1,  # kLAPolicyDeviceOwnerAuthenticationWithBiometrics
            reason,
            delegate.callback_
        )
        
        # Wait for the authentication to complete
        while not delegate.done:
            await asyncio.sleep(0.1)
            NSRunLoop.currentRunLoop().runMode_beforeDate_(
                NSDefaultRunLoopMode,
                NSObject.alloc().init().performSelector_withObject_afterDelay_(None, None, 0.1)
            )
            
        return delegate.success
    
    async def _authenticate_windows(self, reason: str) -> bool:
        """Authenticate on Windows using Windows Hello."""
        try:
            import win32security
            import ctypes
            from ctypes import wintypes
            
            # Constants for Windows Hello
            CREDUIWIN_GENERIC = 0x00000001
            CREDUIWIN_CHECKBOX = 0x00000010
            
            # Set up the credential structure
            class CREDUI_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("hwndParent", wintypes.HWND),
                    ("pszMessageText", wintypes.LPCWSTR),
                    ("pszCaptionText", wintypes.LPCWSTR),
                    ("hbmBanner", wintypes.HBITMAP)
                ]
            
            # Initialize the structure
            info = CREDUI_INFO()
            info.cbSize = ctypes.sizeof(CREDUI_INFO)
            info.pszMessageText = reason
            info.pszCaptionText = "Biometric Authentication"
            
            # Call the credential UI
            flags = CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
            result = win32security.CredUIPromptForWindowsCredentials(
                info, 0, None, None, None, flags
            )
            
            # If we get here, authentication was successful
            return result is not None
            
        except Exception as e:
            logger.error(f"Windows Hello authentication failed: {e}")
            return False
    
    async def _authenticate_linux(self, reason: str) -> bool:
        """Authenticate on Linux using PAM."""
        try:
            import subprocess
            import getpass
            from pathlib import Path
            
            # Try to use the system's authentication
            if Path("/usr/bin/polkit-agent-helper-1").exists():
                proc = await asyncio.create_subprocess_exec(
                    "pkexec", "--user", getpass.getuser(), "true",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                await proc.wait()
                return proc.returncode == 0
                
            # Fallback to PAM
            elif Path("/usr/bin/pamtester").exists():
                proc = await asyncio.create_subprocess_exec(
                    "pamtester", "login", getpass.getuser(), "authenticate",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                await proc.wait()
                return proc.returncode == 0
                
            return False
            
        except Exception as e:
            logger.error(f"Linux authentication failed: {e}")
            return False

# Singleton instance
biometric_auth = BiometricAuth()
