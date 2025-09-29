"""
Tor Network Module for Scrambled Eggs

This module provides functions to make network requests through the Tor network.
"""

import logging
import socket
from pathlib import Path
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import requests

# Configure logging
logger = logging.getLogger(__name__)


def create_connection(address, timeout=None, source_address=None, **kwargs):
    """Create a connection through the Tor SOCKS proxy."""
    from socks import PROXY_TYPE_SOCKS5, socksocket

    host, port = address

    # Create a SOCKS5 socket
    sock = socksocket()
    sock.set_proxy(
        proxy_type=PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050  # Default Tor SOCKS port
    )

    if timeout is not None:
        sock.settimeout(timeout)

    if source_address:
        sock.bind(source_address)

    sock.connect((host, port))
    return sock


class TorSession(requests.Session):
    """A requests.Session that routes all traffic through Tor."""

    def __init__(self, tor_control_port: int = 9051, tor_socks_port: int = 9050, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tor_control_port = tor_control_port
        self.tor_socks_port = tor_socks_port
        self._setup_tor_proxy()

    def _setup_tor_proxy(self):
        """Configure the session to use Tor SOCKS proxy."""
        self.proxies = {
            "http": f"socks5h://127.0.0.1:{self.tor_socks_port}",
            "https": f"socks5h://127.0.0.1:{self.tor_socks_port}",
        }

    def renew_tor_identity(self) -> bool:
        """Request a new Tor circuit (new exit node).

        Returns:
            bool: True if the identity was renewed, False otherwise.
        """
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                return True
        except Exception as e:
            logger.error(f"Failed to renew Tor identity: {e}")
            return False


def get_tor_session(tor_control_port: int = 9051, tor_socks_port: int = 9050) -> TorSession:
    """Create and return a requests Session that routes through Tor.

    Args:
        tor_control_port: Port for Tor control connection
        tor_socks_port: Port for Tor SOCKS proxy

    Returns:
        TorSession: Configured session object
    """
    return TorSession(tor_control_port=tor_control_port, tor_socks_port=tor_socks_port)


# Global session for convenience
tor_session = get_tor_session()


def tor_request(
    method: str, url: str, tor_session: Optional[TorSession] = None, **kwargs
) -> requests.Response:
    """Make an HTTP request through Tor.

    Args:
        method: HTTP method (get, post, etc.)
        url: URL to request
        tor_session: Optional TorSession to use. If None, the global session is used.
        **kwargs: Additional arguments to pass to requests.request()

    Returns:
        requests.Response: The response object
    """
    session = tor_session if tor_session is not None else globals().get("tor_session")
    if session is None:
        session = get_tor_session()

    try:
        response = session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Tor request failed: {e}")
        raise


def check_tor_connection(session: Optional[TorSession] = None) -> bool:
    """Check if the Tor connection is working.

    Args:
        session: Optional TorSession to use. If None, the global session is used.

    Returns:
        bool: True if Tor is working, False otherwise
    """
    check_urls = ["https://check.torproject.org/api/ip", "https://ipinfo.io/json"]

    session = session or globals().get("tor_session")
    if session is None:
        session = get_tor_session()

    for url in check_urls:
        try:
            response = session.get(url, timeout=30)
            data = response.json()

            if "IsTor" in data and data["IsTor"]:
                logger.info(f"Tor connection is working (checked via {url})")
                return True

            if "ip" in data and "country" in data:
                logger.info(
                    f"Tor connection is working. Your IP is {data['ip']} in {data.get('country', 'unknown')}"
                )
                return True

        except Exception as e:
            logger.warning(f"Tor check failed for {url}: {e}")
            continue

    return False
