"""
Settings Manager

Manages application settings with persistence and validation.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from app.core.config import Config

logger = logging.getLogger(__name__)


class SettingsManager:
    """Manages application settings with persistence."""

    # Default settings
    DEFAULT_SETTINGS = {
        # General
        "theme": "System",  # 'System', 'Light', 'Dark'
        "font_size": 12,
        "start_minimized": False,
        "auto_start": False,
        # Network
        "server": "",
        "port": 443,
        "use_proxy": False,
        "proxy_url": "",
        "upload_limit": 0,  # 0 = unlimited
        "download_limit": 0,  # 0 = unlimited
        # Privacy
        "show_typing": True,
        "send_read_receipts": True,
        "show_online_status": True,
        "show_last_seen": True,
        # Security
        "auto_lock_enabled": True,
        "auto_lock_timeout": 5,  # minutes
        "encryption_level": "Standard",  # 'Standard', 'Enhanced', 'Maximum'
        # Notifications
        "notifications_enabled": True,
        "notification_sound": True,
        "notification_preview": True,
        # Media
        "auto_download_media": True,
        "auto_play_gifs": True,
        "save_to_gallery": True,
        "media_download_size_limit": 16,  # MB
        # Data and Storage
        "storage_path": str(Path.home() / "ScrambledEggs"),
        "auto_cleanup": True,
        "auto_cleanup_days": 30,
    }

    def __init__(self, config: Optional[Config] = None):
        """Initialize the settings manager."""
        self.config = config or Config()
        self.settings_file = self.config.get("settings_file", "settings.json")
        self._settings = {}
        self.load_settings()

    def get_settings(self) -> Dict[str, Any]:
        """Get all settings."""
        return {**self.DEFAULT_SETTINGS, **self._settings}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a specific setting."""
        return self._settings.get(key, self.DEFAULT_SETTINGS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        """Set a specific setting."""
        if key in self.DEFAULT_SETTINGS:
            self._settings[key] = value
        else:
            logger.warning(f"Ignoring unknown setting: {key}")

    def update_settings(self, settings: Dict[str, Any]) -> None:
        """Update multiple settings at once."""
        valid_settings = {}
        for key, value in settings.items():
            if key in self.DEFAULT_SETTINGS:
                valid_settings[key] = value
            else:
                logger.warning(f"Ignoring unknown setting: {key}")

        self._settings.update(valid_settings)
        self.save_settings()

    def reset_to_defaults(self) -> None:
        """Reset all settings to default values."""
        self._settings = {}
        self.save_settings()

    def load_settings(self) -> None:
        """Load settings from file."""
        try:
            settings_path = self._get_settings_path()
            if settings_path.exists():
                with open(settings_path, "r", encoding="utf-8") as f:
                    self._settings = json.load(f)
                logger.info("Settings loaded from %s", settings_path)
            else:
                logger.info("No settings file found, using defaults")
                self._settings = {}
        except Exception as e:
            logger.error("Failed to load settings: %s", str(e))
            self._settings = {}

    def save_settings(self) -> None:
        """Save settings to file."""
        try:
            settings_path = self._get_settings_path()
            settings_dir = settings_path.parent

            # Create directory if it doesn't exist
            os.makedirs(settings_dir, exist_ok=True)

            # Save settings
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(self._settings, f, indent=2, ensure_ascii=False)

            logger.debug("Settings saved to %s", settings_path)

        except Exception as e:
            logger.error("Failed to save settings: %s", str(e))

    def _get_settings_path(self) -> Path:
        """Get the path to the settings file."""
        # If settings_file is an absolute path, use it directly
        if os.path.isabs(self.settings_file):
            return Path(self.settings_file)

        # Otherwise, use the config directory
        config_dir = self.config.get("config_dir", Path.home() / ".config" / "scrambled-eggs")
        return Path(config_dir) / self.settings_file

    def get_storage_path(self) -> Path:
        """Get the path for storing application data."""
        storage_path = Path(self.get("storage_path", self.DEFAULT_SETTINGS["storage_path"]))
        os.makedirs(storage_path, exist_ok=True)
        return storage_path

    def get_database_path(self) -> Path:
        """Get the path to the database file."""
        db_dir = self.get_storage_path() / "data"
        os.makedirs(db_dir, exist_ok=True)
        return db_dir / "scrambled_eggs.db"

    def get_cache_path(self) -> Path:
        """Get the path for cache files."""
        cache_dir = self.get_storage_path() / "cache"
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def get_logs_path(self) -> Path:
        """Get the path for log files."""
        logs_dir = self.get_storage_path() / "logs"
        os.makedirs(logs_dir, exist_ok=True)
        return logs_dir

    def get_media_path(self) -> Path:
        """Get the path for media files."""
        media_dir = self.get_storage_path() / "media"
        os.makedirs(media_dir, exist_ok=True)
        return media_dir

    def get_temp_path(self) -> Path:
        """Get the path for temporary files."""
        temp_dir = self.get_storage_path() / "temp"
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir
