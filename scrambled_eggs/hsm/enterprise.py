"""
Enterprise Integration Module for Cloud HSM

This module provides enterprise-grade features for the Cloud HSM client,
including LDAP/Active Directory integration, SIEM integration, and SSO support.
"""

import asyncio
import base64
import json
import logging
import ssl
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

# LDAP/Active Directory integration
try:
    import ldap3
    from ldap3 import ALL, NTLM, SUBTREE, Connection, Server, Tls

    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

# SIEM integration
try:
    from elasticsearch import AsyncElasticsearch
    from opensearchpy import OpenSearch

    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False


class IntegrationType(Enum):
    """Supported integration types."""

    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"
    ELASTICSEARCH = "elasticsearch"
    OPENSEARCH = "opensearch"
    SPLUNK = "splunk"
    SSO = "sso"


class SSOProvider(Enum):
    """Supported SSO providers."""

    OKTA = "okta"
    AUTH0 = "auth0"
    AZURE_AD = "azure_ad"
    GOOGLE = "google"
    KEYCLOAK = "keycloak"


class EnterpriseHSMClient:
    """
    Enterprise HSM client with advanced integration capabilities.

    This class extends the base CloudHSMClient with enterprise features
    such as LDAP/AD integration, SIEM logging, and SSO support.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Enterprise HSM client.

        Args:
            config: Configuration dictionary for enterprise features
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.ldap_conn = None
        self.siem_client = None
        self.sso_provider = None
        self._initialized = False

        # Initialize configured integrations
        self.integrations = {}
        if "integrations" in self.config:
            self._initialize_integrations(self.config["integrations"])

    def _initialize_integrations(self, integrations_config: Dict[str, Any]) -> None:
        """
        Initialize configured integrations.

        Args:
            integrations_config: Configuration for integrations
        """
        for name, config in integrations_config.items():
            try:
                if config["type"] == IntegrationType.LDAP.value:
                    self._init_ldap(config)
                elif config["type"] == IntegrationType.ACTIVE_DIRECTORY.value:
                    self._init_active_directory(config)
                elif config["type"] == IntegrationType.ELASTICSEARCH.value:
                    self._init_elasticsearch(config)
                elif config["type"] == IntegrationType.OPENSEARCH.value:
                    self._init_opensearch(config)
                elif config["type"] == IntegrationType.SSO.value:
                    self._init_sso(config)

                self.integrations[name] = {
                    "type": config["type"],
                    "status": "connected",
                    "config": config,
                }

            except Exception as e:
                self.logger.error(f"Failed to initialize integration {name}: {str(e)}")
                self.integrations[name] = {
                    "type": config.get("type", "unknown"),
                    "status": "error",
                    "error": str(e),
                    "config": config,
                }

    def _init_ldap(self, config: Dict[str, Any]) -> None:
        """
        Initialize LDAP connection.

        Args:
            config: LDAP configuration
        """
        if not LDAP_AVAILABLE:
            raise ImportError("ldap3 is not installed. Install with: pip install ldap3")

        server_url = config["server"]
        bind_dn = config["bind_dn"]
        bind_password = config["bind_password"]
        use_ssl = config.get("use_ssl", True)

        # Configure TLS if using SSL
        tls_config = None
        if use_ssl:
            tls = Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS,
                ca_certs_file=config.get("ca_cert_file"),
            )
            tls_config = tls

        # Connect to LDAP server
        server = Server(server_url, use_ssl=use_ssl, tls=tls_config, get_info=ALL)
        self.ldap_conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

    def _init_active_directory(self, config: Dict[str, Any]) -> None:
        """
        Initialize Active Directory connection.

        Args:
            config: Active Directory configuration
        """
        if not LDAP_AVAILABLE:
            raise ImportError("ldap3 is not installed. Install with: pip install ldap3")

        server_url = config["server"]
        domain = config["domain"]
        username = config["username"]
        password = config["password"]
        use_ssl = config.get("use_ssl", True)

        # Configure TLS if using SSL
        tls_config = None
        if use_ssl:
            tls = Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS,
                ca_certs_file=config.get("ca_cert_file"),
            )
            tls_config = tls

        # Connect to Active Directory
        server = Server(server_url, use_ssl=use_ssl, tls=tls_config, get_info=ALL)
        self.ldap_conn = Connection(
            server,
            user=f"{domain}\\{username}" if domain else username,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )

    def _init_elasticsearch(self, config: Dict[str, Any]) -> None:
        """
        Initialize Elasticsearch client.

        Args:
            config: Elasticsearch configuration
        """
        if not SIEM_AVAILABLE:
            raise ImportError(
                "elasticsearch is not installed. Install with: pip install elasticsearch"
            )

        self.siem_client = AsyncElasticsearch(
            config["hosts"],
            http_auth=(config.get("username"), config.get("password")),
            use_ssl=config.get("use_ssl", True),
            verify_certs=config.get("verify_certs", True),
            ca_certs=config.get("ca_cert_file"),
            timeout=config.get("timeout", 30),
        )

    def _init_opensearch(self, config: Dict[str, Any]) -> None:
        """
        Initialize OpenSearch client.

        Args:
            config: OpenSearch configuration
        """
        if not SIEM_AVAILABLE:
            raise ImportError(
                "opensearch-py is not installed. Install with: pip install opensearch-py"
            )

        self.siem_client = OpenSearch(
            config["hosts"],
            http_auth=(config.get("username"), config.get("password")),
            use_ssl=config.get("use_ssl", True),
            verify_certs=config.get("verify_certs", True),
            ca_certs=config.get("ca_cert_file"),
            timeout=config.get("timeout", 30),
        )

    def _init_sso(self, config: Dict[str, Any]) -> None:
        """
        Initialize SSO provider.

        Args:
            config: SSO configuration
        """
        provider = config.get("provider")
        if not provider:
            raise ValueError("SSO provider must be specified in config")

        self.sso_provider = SSOProvider(provider.lower())

        # Store SSO configuration
        self.sso_config = {
            "client_id": config["client_id"],
            "client_secret": config.get("client_secret"),
            "redirect_uri": config.get("redirect_uri"),
            "scope": config.get("scope", "openid profile email"),
            "authorization_endpoint": config.get("authorization_endpoint"),
            "token_endpoint": config.get("token_endpoint"),
            "userinfo_endpoint": config.get("userinfo_endpoint"),
            "jwks_uri": config.get("jwks_uri"),
        }

    async def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate a user against LDAP/Active Directory.

        Args:
            username: Username to authenticate
            password: User's password

        Returns:
            Dictionary with authentication result and user details
        """
        if not self.ldap_conn:
            raise RuntimeError("LDAP/AD connection not initialized")

        try:
            # Try to bind with the provided credentials
            temp_conn = self.ldap_conn.server.connection_factory()
            temp_conn.open()

            # Format the user DN based on the connection type
            if self.ldap_conn.authentication == NTLM:
                # For Active Directory
                temp_conn.bind()
                search_filter = f"(sAMAccountName={username})"
                base_dn = self.ldap_conn.server.info.other.get("defaultNamingContext", [""])[0]

                # Search for the user
                if temp_conn.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=["*"],
                ):
                    user_dn = temp_conn.entries[0].entry_dn
                    # Try to bind with the user's DN and password
                    if temp_conn.rebind(user=user_dn, password=password):
                        # Get user details
                        user_attrs = temp_conn.entries[0].entry_attributes_as_dict
                        return {
                            "authenticated": True,
                            "username": username,
                            "dn": user_dn,
                            "attributes": user_attrs,
                        }
            else:
                # For standard LDAP
                user_dn = f"uid={username},{self.ldap_conn.server.info.other.get('defaultNamingContext', [''])[0]}"
                if temp_conn.rebind(user=user_dn, password=password):
                    # Get user details
                    user_attrs = {}
                    return {
                        "authenticated": True,
                        "username": username,
                        "dn": user_dn,
                        "attributes": user_attrs,
                    }

            return {"authenticated": False, "error": "Invalid credentials"}

        except Exception as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            return {"authenticated": False, "error": str(e)}

        finally:
            if "temp_conn" in locals() and temp_conn.bound:
                temp_conn.unbind()

    async def log_security_event(self, event: Dict[str, Any]) -> bool:
        """
        Log a security event to the SIEM.

        Args:
            event: Event data to log

        Returns:
            True if the event was logged successfully, False otherwise
        """
        if not self.siem_client:
            self.logger.warning("SIEM client not initialized, cannot log event")
            return False

        try:
            # Add timestamp if not provided
            if "@timestamp" not in event:
                event["@timestamp"] = datetime.utcnow().isoformat()

            # Index the document
            if isinstance(self.siem_client, AsyncElasticsearch):
                await self.siem_client.index(
                    index=self.config.get("siem_index", "security-events"), document=event
                )
            else:  # OpenSearch
                await self.siem_client.index(
                    index=self.config.get("siem_index", "security-events"), body=event
                )

            return True

        except Exception as e:
            self.logger.error(f"Failed to log security event: {str(e)}")
            return False

    async def get_sso_login_url(self, state: str = None, **kwargs) -> str:
        """
        Get the SSO login URL.

        Args:
            state: Optional state parameter for CSRF protection
            **kwargs: Additional parameters for the authorization request

        Returns:
            The SSO login URL
        """
        if not self.sso_provider:
            raise RuntimeError("SSO provider not configured")

        # Generate a random state if not provided
        if not state:
            import secrets

            state = secrets.token_urlsafe(32)

        # Build the authorization URL
        params = {
            "response_type": "code",
            "client_id": self.sso_config["client_id"],
            "redirect_uri": self.sso_config["redirect_uri"],
            "scope": self.sso_config["scope"],
            "state": state,
            **kwargs,
        }

        # Add provider-specific parameters
        if self.sso_provider == SSOProvider.OKTA:
            params["response_mode"] = "query"

        # Build the query string
        from urllib.parse import urlencode

        query_string = urlencode(params)

        return f"{self.sso_config['authorization_endpoint']}?{query_string}"

    async def exchange_code_for_token(self, code: str, **kwargs) -> Dict[str, Any]:
        """
        Exchange an authorization code for an access token.

        Args:
            code: Authorization code from the SSO provider
            **kwargs: Additional parameters for the token request

        Returns:
            Token response from the SSO provider
        """
        if not self.sso_provider:
            raise RuntimeError("SSO provider not configured")

        import aiohttp

        # Prepare the token request
        token_url = self.sso_config["token_endpoint"]
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.sso_config["redirect_uri"],
            "client_id": self.sso_config["client_id"],
            "client_secret": self.sso_config["client_secret"],
            **kwargs,
        }

        # Make the token request
        async with aiohttp.ClientSession() as session:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            async with session.post(token_url, data=data, headers=headers) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Exception(f"Failed to exchange code for token: {error}")

                return await response.json()

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information using an access token.

        Args:
            access_token: Access token from the SSO provider

        Returns:
            User information from the SSO provider
        """
        if not self.sso_provider:
            raise RuntimeError("SSO provider not configured")

        import aiohttp

        # Get the user info endpoint
        user_info_url = self.sso_config["userinfo_endpoint"]

        # Make the user info request
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            async with session.get(user_info_url, headers=headers) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Exception(f"Failed to get user info: {error}")

                return await response.json()

    async def close(self) -> None:
        """Close all connections and release resources."""
        if self.ldap_conn and self.ldap_conn.bound:
            self.ldap_conn.unbind()

        if self.siem_client:
            if isinstance(self.siem_client, AsyncElasticsearch):
                await self.siem_client.close()
            elif hasattr(self.siem_client, "close"):
                self.siem_client.close()

        self._initialized = False


# Example usage
if __name__ == "__main__":
    import asyncio

    # Example configuration
    config = {
        "integrations": {
            "active_directory": {
                "type": "active_directory",
                "server": "ldap://ad.example.com",
                "domain": "EXAMPLE",
                "username": "service-account",
                "password": "password",
                "use_ssl": True,
                "ca_cert_file": "/path/to/ca.crt",
            },
            "siem": {
                "type": "elasticsearch",
                "hosts": ["https://elasticsearch.example.com:9200"],
                "username": "elastic",
                "password": "password",
                "use_ssl": True,
                "verify_certs": True,
                "ca_cert_file": "/path/to/ca.crt",
                "siem_index": "security-events",
            },
            "sso": {
                "type": "sso",
                "provider": "okta",
                "client_id": "your-client-id",
                "client_secret": "your-client-secret",
                "redirect_uri": "https://your-app.example.com/callback",
                "scope": "openid profile email",
                "authorization_endpoint": "https://your-okta-domain.okta.com/oauth2/v1/authorize",
                "token_endpoint": "https://your-okta-domain.okta.com/oauth2/v1/token",
                "userinfo_endpoint": "https://your-okta-domain.okta.com/oauth2/v1/userinfo",
                "jwks_uri": "https://your-okta-domain.okta.com/oauth2/v1/keys",
            },
        }
    }

    async def main():
        # Initialize the enterprise HSM client
        hsm = EnterpriseHSMClient(config)

        try:
            # Example: Authenticate a user
            result = await hsm.authenticate_user("johndoe", "password")
            print(f"Authentication result: {result}")

            # Example: Log a security event
            event = {
                "event_type": "authentication",
                "user": "johndoe",
                "status": "success" if result.get("authenticated") else "failure",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "details": {"method": "password", "provider": "active_directory"},
            }

            logged = await hsm.log_security_event(event)
            print(f"Event logged: {logged}")

            # Example: Get SSO login URL
            if "sso" in hsm.integrations:
                login_url = await hsm.get_sso_login_url()
                print(f"SSO Login URL: {login_url}")

        finally:
            # Clean up
            await hsm.close()

    # Run the example
    asyncio.run(main())
