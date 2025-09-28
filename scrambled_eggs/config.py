""
"""
Configuration management for Scrambled Eggs P2P Messaging.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

class Config:
    """Configuration manager for Scrambled Eggs."""
    
    # Default configuration
    DEFAULTS = {
        # Antarctica routing settings
        "antarctica_routing": {
            "enabled": True,  # Enable/disable Antarctica routing
            "proxies": [
                "antarctica-proxy1.example.com:3128",
                "antarctica-proxy2.example.com:3128",
                "antarctica-proxy3.example.com:3128"
            ],
            "coordinates": {
                "latitude": -82.8628,
                "longitude": 135.0
            },
            "timeout": 30.0,  # Request timeout in seconds
            "max_retries": 3,  # Number of retries for failed requests
            "rotate_proxies": True,  # Rotate between available proxies
            "verify_ssl": False  # Disable SSL verification for proxies
        },
        
        # Tor settings
        "tor": {
            "enabled": False,  # Enable/disable Tor integration
            "use_system_tor": True,  # Use system Tor if available
            "tor_path": None,  # Path to Tor executable (None for auto-detect)
            "data_dir": None,  # Directory to store Tor data (None for temp dir)
            "control_port": 9051,  # Tor control port
            "socks_port": 9050,  # Tor SOCKS port
            "http_tunnel_port": 8118,  # HTTP tunnel port (for HTTP requests)
            "dns_port": 5353,  # DNS port (for DNS over Tor)
            "use_bridges": False,  # Use Tor bridges for censorship circumvention
            "bridges": [],  # List of bridge configurations
            "use_obfs4": False,  # Use obfs4 obfuscation
            "use_meek": False,  # Use meek for censorship circumvention
            "use_snowflake": False,  # Use Snowflake for censorship circumvention
            "use_stealth": False,  # Use stealth mode for hidden services
            "use_vanguards": True,  # Use Vanguards for better security
            "use_ntor_v3": True,  # Use ntor v3 handshake
            "use_microdescriptors": True,  # Use microdescriptors for smaller downloads
            "use_sandbox": True,  # Use sandboxing for Tor process
            "circuit_timeout": 120,  # Circuit build timeout in seconds
            "max_circuit_dirtiness": 600,  # Maximum circuit lifetime in seconds
            "new_circuit_period": 30,  # How often to build new circuits (seconds)
            "num_entry_guards": 3,  # Number of entry guards to use
            "enforce_distinct_subnets": True,  # Don't use multiple nodes in same /16
            "exclude_nodes": [],  # List of node fingerprints to exclude
            "exclude_exit_nodes": [],  # List of exit node fingerprints to exclude
            "exit_nodes": [],  # List of exit nodes to prefer (comma-separated)
            "geoip_exclude_nodes": [],  # List of country codes to exclude
            "strict_nodes": False,  # Only use specified nodes
            "hidserv_auth": [],  # Hidden service authorization cookies
            "onion_services": {  # Configuration for hidden services
                "enabled": False,  # Enable hidden services
                "data_dir": None,  # Directory to store hidden service keys
                "version": 3,  # Onion service version (2 or 3)
                "ports": [  # List of port mappings
                    {
                        "virtual_port": 80,  # Port on the hidden service
                        "target_address": "127.0.0.1",  # Target address
                        "target_port": 8080  # Target port
                    }
                ],
                "client_auth": False,  # Require client authentication
                "max_streams": 10,  # Maximum number of simultaneous streams
                "single_hop": False,  # Use single-hop (less secure) hidden services
                "non_anonymous": False,  # Disable anonymity for this service
                "auth_cookie": None,  # Authentication cookie for the control port
                "auth_cookie_file": None  # File containing the authentication cookie
            },
            "logging": {
                "level": "notice",  # none, debug, info, notice, warn, err
                "log_file": None,  # Path to log file (None for stderr)
                "log_to_console": True,  # Log to console
                "log_rotating": True,  # Enable log rotation
                "max_log_size": 10485760,  # 10MB max log size
                "max_log_files": 5  # Number of log files to keep
            },
            "security": {
                "safe_logging": True,  # Redact sensitive information from logs
                "disable_debugger_attachment": True,  # Prevent debugger attachment
                "protect_process_memory": True,  # Protect sensitive memory
                "sandbox": 1,  # Sandbox level (0=disabled, 1=relaxed, 2=strict)
                "hardware_accel": True,  # Use hardware acceleration if available
                "test_socks": True,  # Test SOCKS proxy after start
                "test_reachability": True,  # Test network reachability
                "allow_missing_torrc": True,  # Allow running without torrc
                "allow_missing_geoip": True,  # Allow running without GeoIP data
                "allow_missing_geoipv6": True,  # Allow running without IPv6 GeoIP data
                "allow_missing_pt_state": True,  # Allow running without pluggable transports state
                "allow_missing_tor_pt_exec": True,  # Allow running without pluggable transports
                "allow_missing_tor_pt_client": True,  # Allow running without pluggable transport clients
                "allow_missing_tor_pt_proxy": True,  # Allow running without pluggable transport proxies
                "allow_missing_tor_pt_helper": True,  # Allow running without pluggable transport helpers
                "allow_missing_tor_pt_verifier": True,  # Allow running without pluggable transport verifiers
                "allow_missing_tor_pt_config": True  # Allow running without pluggable transport config
            },
            "performance": {
                "num_cpus": 0,  # Number of CPUs to use (0=auto)
                "avoid_disk_writes": False,  # Minimize disk writes
                "circuit_priority": 0,  # Circuit priority (-1 to 1)
                "dormant_client_timeout": 0,  # Time before going dormant (0=disabled)
                "dormant_canceled_by_startup": False,  # Cancel dormant mode on startup
                "dormant_canceled_by_startup_events": True,  # Cancel dormant mode on startup events
                "dormant_disable_intro_circuits": True,  # Disable intro circuits in dormant mode
                "dormant_disabled_loop_events": False,  # Disable loop events in dormant mode
                "dormant_enabled": True,  # Enable dormant mode
                "dormant_idle_timeout": 0,  # Time before going dormant when idle (0=disabled)
                "dormant_limit_soft": 0,  # Soft limit for dormant mode (0=disabled)
                "dormant_limit_hard": 0,  # Hard limit for dormant mode (0=disabled)
                "dormant_on_startup": False,  # Start in dormant mode
                "dormant_optimistic_data_okay": True  # Optimistic data is okay in dormant mode
            },
            "network": {
                "reachable_addresses": "*:80,*:443",  # Reachable addresses
                "reachable_ports": "80,443",  # Reachable ports
                "reachable_dir_ports": "80,443",  # Reachable directory ports
                "reachable_or_ports": "80,443",  # Reachable OR ports
                "reachable_socks_ports": "9050,9150",  # Reachable SOCKS ports
                "reachable_http_ports": "80,8080,443,8443",  # Reachable HTTP ports
                "reachable_https_ports": "443,8443",  # Reachable HTTPS ports
                "reachable_dir_addresses": "*:80,*:443",  # Reachable directory addresses
                "reachable_or_addresses": "*:80,*:443",  # Reachable OR addresses
                "reachable_socks_addresses": "*:9050,*:9150",  # Reachable SOCKS addresses
                "reachable_http_addresses": "*:80,*:8080,*:443,*:8443",  # Reachable HTTP addresses
                "reachable_https_addresses": "*:443,*:8443"  # Reachable HTTPS addresses
            },
            "bridges": {
                "type": "obfs4",  # Bridge type (obfs4, meek, snowflake, etc.)
                "address": "",  # Bridge address
                "port": 0,  # Bridge port
                "fingerprint": "",  # Bridge fingerprint
                "cert": "",  # Bridge certificate
                "iat_mode": 0,  # IAT mode (0=disabled, 1=enabled, 2=paranoid)
                "socks4_proxy": "",  # SOCKS4 proxy for bridge
                "socks5_proxy": "",  # SOCKS5 proxy for bridge
                "socks5_username": "",  # SOCKS5 username
                "socks5_password": "",  # SOCKS5 password
                "socks5_protocol_username": "",  # SOCKS5 protocol username
                "socks5_protocol_password": ""  # SOCKS5 protocol password
            },
            "advanced": {
                "client_only": True,  # Don't act as a relay
                "disable_network": False,  # Disable all network activity
                "exclude_nodes": "",  # Exclude nodes by fingerprint
                "exclude_exit_nodes": "",  # Exclude exit nodes by fingerprint
                "exit_nodes": "",  # Use only these nodes as exits
                "geoip_exclude_nodes": "",  # Exclude nodes by country code
                "hiddenservicedir": "",  # Hidden service directory
                "hiddenserviceport": "",  # Hidden service ports
                "hiddenserviceversion": "3",  # Hidden service version (2 or 3)
                "hiddenserviceauthorizeclient": "",  # Authorized clients
                "hiddenserviceoptions": "",  # Hidden service options
                "hiddenservicenonanonymous": "0",  # Non-anonymous hidden service
                "hiddenservicenonanonymousmode": "",  # Non-anonymous mode
                "hiddenservicenonanonymousgroup": "",  # Non-anonymous group
                "hiddenserviceexportcircuitid": "",  # Export circuit ID
                "hiddenservicemaxstreams": "0",  # Maximum streams
                "hiddenservicemaxstreamsclosecircuit": "0",  # Close circuit on max streams
                "hiddenservicetor2webmode": "0",  # Tor2web mode
                "hiddenserviceallowunknownports": "0",  # Allow unknown ports
                "hiddenserviceallowunknownports_public": "0",  # Allow unknown public ports
                "hiddenserviceallowunknownports_private": "0",  # Allow unknown private ports
                "hiddenserviceallowunknownports_isolated": "0",  # Allow unknown isolated ports
                "hiddenserviceallowunknownports_non_anonymous": "0",  # Allow unknown non-anonymous ports
                "hiddenserviceallowunknownports_public_non_anonymous": "0",  # Allow unknown public non-anonymous ports
                "hiddenserviceallowunknownports_private_non_anonymous": "0",  # Allow unknown private non-anonymous ports
                "hiddenserviceallowunknownports_isolated_non_anonymous": "0"  # Allow unknown isolated non-anonymous ports
            }
        },
        # Application settings
        "app": {
            "name": "Scrambled Eggs P2P",
            "version": "1.1.0",
            "data_dir": str(Path.home() / ".scrambled-eggs"),
            "cache_dir": str(Path.home() / ".cache" / "scrambled-eggs"),
            "log_dir": str(Path.home() / ".local" / "share" / "scrambled-eggs" / "logs"),
        },
        
        # Security settings
        "security": {
            "key_derivation": {
                "algorithm": "argon2id",  # Options: argon2id, scrypt, pbkdf2
                "iterations": 100000,     # For PBKDF2
                "memory_cost": 65536,     # For Argon2 (in KB)
                "parallelism": 4,         # For Argon2
                "key_length": 32,         # 256 bits
                "salt_length": 16
            },
            "encryption": {
                "algorithm": "aes-256-gcm",
                "initial_layers": 100,    # For self-modifying encryption
                "min_layer_increase": 5,  # For self-modifying encryption
                "max_layer_increase": 50, # For self-modifying encryption
                "layer_growth_factor": 1.1,
                "aes_key_size": 32,       # 256 bits
                "rsa_key_size": 4096,
                "ecc_curve": "secp384r1", # Elliptic curve for ECDH
                "max_ram_usage_mb": 1024,  # Maximum RAM to use for encryption (MB)
                "target_encryption_time_ms": 1000
            },
            "breach_detection": {
                "enabled": True,
                "suspicion_threshold": 0.8,
                "max_attempts_before_delay": 3,
                "delay_factor": 2.0  # Exponential backoff factor
            },
            "perfect_forward_secrecy": True,
            "message_authentication": True,
            "ephemeral_messages": {
                "enabled": True,
                "default_ttl": 3600  # 1 hour in seconds
            }
        },
        
        # P2P and WebRTC settings
        "p2p": {
            "signaling_servers": [
                {
                    "url": "ws://localhost:8000/ws/",
                    "priority": 1,
                    "enabled": True
                },
                # Add more signaling servers as fallbacks
            ],
            "stun_servers": [
                "stun:stun.l.google.com:19302",
                "stun:stun1.l.google.com:19302",
                "stun:stun2.l.google.com:19302"
            ],
            "turn_servers": [
                # Example TURN server configuration
                # {
                #     "urls": ["turn:turn.example.com"],
                #     "username": "username",
                #     "credential": "password"
                # }
            ],
            "ice_transport_policy": "all",  # 'all' or 'relay'
            "bundle_policy": "balanced",
            "rtcp_mux_policy": "require",
            "sdp_semantics": "unified-plan",
            "enable_dtls_srtp": True,
            "enable_rtp_data_channel": False,
            "enable_ice_tcp": True,
            "ice_candidate_pool_size": 1,
            "ice_servers_refresh_interval": 3600,  # 1 hour in seconds
            "connection_timeout": 30,  # seconds
            "keepalive_interval": 25,  # seconds (should be < connection_timeout)
            "max_message_size": 16 * 1024 * 1024,  # 16MB
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "enable_bandwidth_estimation": True,
            "preferred_codecs": {
                "audio": ["opus"],
                "video": ["VP8", "H264"]
            }
        },
        
        # Media settings
        "media": {
            "audio": {
                "enabled": True,
                "codec": "opus",
                "bitrate": 128,  # kbps
                "sample_rate": 48000,  # Hz
                "channels": 2,
                "echo_cancellation": True,
                "noise_suppression": True,
                "auto_gain_control": True,
                "highpass_filter": True,
                "stereo_swapping": False,
                "audio_jitter_buffer_max_packets": 100,
                "audio_jitter_buffer_fast_accelerate": False,
                "audio_jitter_buffer_min_delay_ms": 0
            },
            "video": {
                "enabled": True,
                "codec": "VP8",
                "bitrate": 2000,  # kbps
                "width": 1280,
                "height": 720,
                "frame_rate": 30,
                "max_bitrate": 4000,  # kbps
                "min_bitrate": 300,   # kbps
                "max_framerate": 30,
                "min_framerate": 15,
                "max_pixel_count": 1280 * 720,
                "max_pixel_count_ratio": 1.0,
                "screencast_max_pixel_count": 1920 * 1080,
                "screencast_max_pixel_count_ratio": 1.0,
                "screencast_max_bitrate": 4000,  # kbps
                "screencast_max_framerate": 24
            },
            "screensharing": {
                "enabled": True,
                "default_source": "screen",  # 'screen', 'window', or 'tab'
                "constraints": {
                    "video": {
                        "cursor": "always",  # 'always', 'motion', or 'never'
                        "displaySurface": "monitor",  # 'monitor', 'window', or 'application'
                        "logicalSurface": True,
                        "resizeMode": "crop-and-scale"  # 'none', 'crop-and-scale', or 'scale'
                    }
                }
            },
            "data_channels": {
                "reliable": True,
                "ordered": True,
                "max_retransmits": None,  # None for reliable, or a number for unreliable
                "max_packet_life_time": None,  # ms, None for reliable
                "negotiated": False,
                "id": None,
                "protocol": "sctp",
                "priority": "high",  # 'very-low', 'low', 'medium', or 'high'
                "max_retransmit_time": 3000  # ms
            }
        },
        
        # Performance settings
        "performance": {
            "max_workers": None,  # None = use all available cores
            "chunk_size": 1024 * 1024,  # 1MB chunks for large files
            "use_memoryview": True,
            "enable_hardware_acceleration": True,
            "prefer_hw_video_codecs": True,
            "prefer_hw_audio_codecs": True,
            "enable_desktop_capture_sharing": True,
            "enable_gpu_memory_buffer_video_frames": True,
            "enable_rtp_data_channel": False,
            "enable_dtls_srtp": True,
            "enable_ice_tcp": True,
            "enable_ice_renomination": True,
            "enable_ice_tcp_candidate": True,
            "enable_ice_udp_mux": True,
            "enable_rtc_stats": True,
            "enable_rtc_stats_dump": False,
            "rtc_stats_dump_interval": 30,  # seconds
            "max_cpu_usage_percent": 80,  # Maximum CPU usage before throttling
            "max_memory_usage_percent": 80,  # Maximum memory usage before throttling
            "network_quality_estimation_interval": 5  # seconds
        },
        
        # Logging settings
        "logging": {
            "level": "INFO",  # DEBUG, INFO, WARNING, ERROR, CRITICAL
            "file": None,  # Path to log file, or None for stderr
            "max_size": 10 * 1024 * 1024,  # 10MB
            "backup_count": 5,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "enable_console_logging": True,
            "enable_file_logging": True,
            "log_webrtc_events": True,
            "log_rtp_packets": False,
            "log_rtcp_packets": False,
            "log_sctp_packets": False,
            "log_data_channel_messages": False
        },
        
        # User interface settings
        "ui": {
            "theme": "system",  # 'light', 'dark', or 'system'
            "font_family": "Arial, sans-serif",
            "font_size": 12,  # in points
            "message_font_size": 14,  # in points
            "show_typing_indicators": True,
            "show_read_receipts": True,
            "show_link_previews": True,
            "spell_check": True,
            "auto_download_media": True,
            "auto_play_gifs": True,
            "auto_play_videos": False,
            "auto_load_images": True,
            "auto_show_images": True,
            "auto_show_videos": False,
            "auto_show_audio": True,
            "auto_show_documents": True,
            "auto_show_other_files": True,
            "auto_accept_calls": False,
            "ringtone": "default",
            "notification_sound": "default",
            "notification_duration": 5000,  # ms
            "notification_position": "top-right",  # 'top-left', 'top-right', 'bottom-left', 'bottom-right'
            "notification_enabled": True,
            "notification_show_preview": True,
            "notification_show_sender": True,
            "notification_show_message": True,
            "notification_show_reaction_emoji": True,
            "notification_play_sound": True,
            "notification_bounce_icon": True,
            "notification_flash_window": True,
            "notification_desktop_alerts": True,
            "notification_disable_when_active": False,
            "notification_mark_as_read_on_open": True,
            "notification_mark_as_read_on_reply": True,
            "notification_mark_as_read_on_dismiss": True,
            "notification_mark_as_read_on_click": True
        },
        
        # Privacy settings
        "privacy": {
            "block_cross_site_tracking": True,
            "send_read_receipts": True,
            "share_typing_indicators": True,
            "share_online_status": True,
            "share_last_seen": "everyone",  # 'everyone', 'contacts', 'nobody'
            "share_profile_photo": "everyone",
            "share_about": "everyone",
            "share_phone_number": "contacts",
            "share_email_address": "contacts",
            "sync_contacts": True,
            "upload_contacts": True,
            "allow_contact_discovery": True,
            "link_previews": True,
            "auto_update_contacts": True,
            "auto_download_updates": True,
            "auto_install_updates": False,
            "send_crash_reports": False,
            "send_usage_statistics": False,
            "remember_recent_files": True,
            "remember_recent_emojis": True,
            "remember_recent_stickers": True,
            "remember_recent_gifs": True,
            "remember_recent_sticker_packs": True,
            "remember_recent_hashtags": True,
            "remember_recent_mentions": True,
            "remember_recent_links": True,
            "remember_recent_locations": True
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_path: Path to configuration file. If None, uses default location.
        """
        self.config_path = config_path or self.get_default_config_path()
        self._config = self._load_config()
    
    @classmethod
    def get_default_config_path(cls) -> str:
        """Get the default configuration file path."""
        config_dir = os.path.join(os.path.expanduser("~"), ".config", "scrambled-eggs")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "config.json")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return self._merge_configs(self.DEFAULTS, json.load(f))
        except Exception as e:
            print(f"Warning: Failed to load config from {self.config_path}: {e}")
        
        # Return defaults if loading fails
        return self.DEFAULTS.copy()
    
    def save(self, path: Optional[str] = None) -> None:
        """Save configuration to file."""
        path = path or self.config_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self._config, f, indent=2)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot notation."""
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by dot notation."""
        keys = key.split('.')
        current = self._config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]) -> None:
        """Update multiple configuration values."""
        for key, value in updates.items():
            self.set(key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Return the configuration as a dictionary."""
        return self._config.copy()
    
    @staticmethod
    def _merge_configs(base: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge two configuration dictionaries."""
        result = base.copy()
        
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._merge_configs(result[key], value)
            else:
                result[key] = value
                
        return result

# Global configuration instance
config = Config()

def get_config() -> Config:
    """Get the global configuration instance."""
    return config

def init_config(config_path: Optional[str] = None) -> Config:
    """Initialize the global configuration."""
    global config
    config = Config(config_path)
    return config
