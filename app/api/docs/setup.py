"""
API Documentation Setup.

This module provides functionality to set up and customize API documentation
using FastAPI and Swagger UI.
"""

from typing import Any, Dict, Optional
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
import json
import os


class APIDocumentation:
    """Handles API documentation generation and customization."""

    def __init__(self, app: FastAPI) -> None:
        """Initialize with a FastAPI application instance.
        
        Args:
        """
        self.app = app
        self._custom_docs: Dict[str, Dict[str, Any]] = {}
    
    def add_custom_docs(self, route_path: str, docs: Dict[str, Any]) -> None:
        """Add custom documentation for a specific route.
        
        Args:
            route_path: The URL path of the route to document
            docs: Dictionary containing OpenAPI documentation for the route
        """
        self._custom_docs[route_path] = docs
    
    def generate_openapi(self) -> Dict[str, Any]:
        """Generate OpenAPI schema with custom documentation.
        
        Returns:
            Dict containing the complete OpenAPI schema
        """
        if not self.app.openapi_schema:
            self.app.openapi_schema = get_openapi(
                title=self.app.title,
                version=self.app.version,
                openapi_version=self.app.openapi_version,
                description=self.app.description,
                routes=self.app.routes,
                tags=self.app.openapi_tags,
                servers=self.app.servers,
            )

            # Apply custom documentation
            for route in self.app.routes:
                if isinstance(route, APIRoute) and route.path in self._custom_docs:
                    path_item = self._custom_docs[route.path]
                    if path_item:
                        for method in path_item:
                            if method in self.app.openapi_schema["paths"][route.path]:
                                self.app.openapi_schema["paths"][route.path][method].update(
                                    path_item[method]
                                )

        return self.app.openapi_schema
    
    def generate_swagger_ui_html(self) -> str:
        """Generate custom Swagger UI HTML.
        
        Returns:
            HTML content for the Swagger UI interface
        """
        return get_swagger_ui_html(
            openapi_url=self.app.openapi_url,
            title=f"{self.app.title} - Swagger UI",
            oauth2_redirect_url=self.app.swagger_ui_oauth2_redirect_url,
            swagger_js_url="/static/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui.css",
        )
    
    def save_openapi_spec(self, output_file: str = "openapi.json") -> None:
        """Save OpenAPI spec to a JSON file.
        
        Args:
            output_file: Path where to save the OpenAPI spec file
        """
        spec = self.generate_openapi()
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(spec, f, ensure_ascii=False, indent=2)
        print(f"OpenAPI spec saved to {output_file}")


def setup_api_docs(app: FastAPI) -> APIDocumentation:
    """Set up API documentation for a FastAPI application.
    
    Args:
        app: The FastAPI application to set up documentation for
        
    Returns:
        APIDocumentation instance for further customization
    """
    # Configure basic API information
    app.title = "Scrambled Eggs API"
    app.description = """
    ## Scrambled Eggs API
    
    This is the official API documentation for Scrambled Eggs, a secure messaging platform.
    
    ### Authentication
    Most endpoints require authentication. Use the `/auth` endpoints to get an access token.
    """
    app.version = "1.0.0"
    
    # Initialize documentation
    docs = APIDocumentation(app)
    
    # Add custom documentation for specific routes
    docs.add_custom_docs(
        "/api/v1/messages",
        {
            "get": {
                "summary": "Get messages",
                "description": "Retrieve messages for the authenticated user",
                "parameters": [
                    {
                        "name": "conversation_id",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                        "description": "ID of the conversation"
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer", "default": 50},
                        "description": "Maximum number of messages to return"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "List of messages",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Message"}
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    
    # Add OpenAPI route
    @app.get("/openapi.json", include_in_schema=False)
    async def get_openapi() -> Dict[str, Any]:
        """Return the OpenAPI schema."""
        return docs.generate_openapi()
    
    # Add Swagger UI route
    @app.get("/docs", include_in_schema=False)
    async def get_swagger_ui():
        """Serve the Swagger UI interface."""
        return docs.generate_swagger_ui_html()
    
    # Save OpenAPI spec on startup
    @app.on_event("startup")
    async def save_docs():
        """Save OpenAPI spec to file on application startup."""
        docs.save_openapi_spec("docs/openapi.json")
    
    return docs
