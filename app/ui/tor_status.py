"""
Tor status and control interface for the web UI.
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify

from ...network.tor_manager import tor_manager

# Configure logging
logger = logging.getLogger(__name__)

# Create Blueprint
tor_bp = Blueprint("tor", __name__, url_prefix="/tor")

# Global state for circuit visualization
circuit_visualization = {"nodes": [], "links": [], "last_updated": None}


@tor_bp.route("/status")
def get_status():
    """Get the current Tor connection status."""
    try:
        status = tor_manager.get_connection_status()
        return jsonify({"success": True, "status": status})
    except Exception as e:
        logger.exception("Error getting Tor status")
        return jsonify({"success": False, "error": str(e)}), 500


@tor_bp.route("/circuits")
def list_circuits():
    """List all active Tor circuits."""
    try:
        circuits = tor_manager.get_all_circuits()
        return jsonify({"success": True, "circuits": circuits})
    except Exception as e:
        logger.exception("Error listing Tor circuits")
        return jsonify({"success": False, "error": str(e)}), 500


@tor_bp.route("/new-identity", methods=["POST"])
def new_identity():
    """Request a new Tor identity (new circuit)."""
    try:
        success = tor_manager.new_identity()
        return jsonify(
            {
                "success": success,
                "message": (
                    "New identity requested" if success else "Failed to request new identity"
                ),
            }
        )
    except Exception as e:
        logger.exception("Error requesting new Tor identity")
        return jsonify({"success": False, "error": str(e)}), 500


@tor_bp.route("/network-info")
def network_info():
    """Get information about the Tor network."""
    try:
        info = tor_manager.get_network_info()
        return jsonify({"success": True, "info": info})
    except Exception as e:
        logger.exception("Error getting Tor network info")
        return jsonify({"success": False, "error": str(e)}), 500


def update_circuit_visualization():
    """Update the circuit visualization data."""
    global circuit_visualization

    try:
        status = tor_manager.get_connection_status()
        if not status.get("connected"):
            circuit_visualization = {
                "nodes": [],
                "links": [],
                "last_updated": datetime.utcnow().isoformat(),
                "error": "Not connected to Tor",
            }
            return

        # Get all circuits
        circuits = status.get("circuits", [])

        # Reset visualization data
        nodes = []
        links = []
        node_ids = set()

        # Add client node
        client_id = "client"
        nodes.append({"id": client_id, "name": "You", "type": "client", "status": "online"})
        node_ids.add(client_id)

        # Process each circuit
        for circuit in circuits:
            if not circuit.get("built", False) or not circuit.get("path"):
                continue

            # Add entry node
            entry_node_id = circuit["path"][0] if circuit["path"] else None
            if entry_node_id and entry_node_id not in node_ids:
                nodes.append(
                    {
                        "id": entry_node_id,
                        "name": f"Entry ({entry_node_id[:6]}...)",
                        "type": "entry",
                        "status": "online",
                    }
                )
                node_ids.add(entry_node_id)

                # Link client to entry node
                links.append(
                    {
                        "source": client_id,
                        "target": entry_node_id,
                        "type": "client-to-entry",
                        "circuit_id": circuit["id"],
                    }
                )

            # Add middle nodes
            for i, node_id in enumerate(circuit["path"][1:-1]):
                if node_id not in node_ids:
                    nodes.append(
                        {
                            "id": node_id,
                            "name": f"Middle {i+1} ({node_id[:6]}...)",
                            "type": "middle",
                            "status": "online",
                        }
                    )
                    node_ids.add(node_id)

                # Link to previous node
                prev_node = circuit["path"][i] if i > 0 else entry_node_id
                if prev_node and node_id != prev_node:
                    links.append(
                        {
                            "source": prev_node,
                            "target": node_id,
                            "type": "relay",
                            "circuit_id": circuit["id"],
                        }
                    )

            # Add exit node
            if len(circuit["path"]) > 1:
                exit_node_id = circuit["path"][-1]
                if exit_node_id not in node_ids:
                    nodes.append(
                        {
                            "id": exit_node_id,
                            "name": f"Exit ({exit_node_id[:6]}...)",
                            "type": "exit",
                            "status": "online",
                        }
                    )
                    node_ids.add(exit_node_id)

                    # Link to last middle node
                    last_middle = circuit["path"][-2] if len(circuit["path"]) > 1 else entry_node_id
                    if last_middle and exit_node_id != last_middle:
                        links.append(
                            {
                                "source": last_middle,
                                "target": exit_node_id,
                                "type": "relay",
                                "circuit_id": circuit["id"],
                            }
                        )

                # Add destination node for this circuit
                dest_id = f"dest_{circuit['id']}"
                nodes.append(
                    {
                        "id": dest_id,
                        "name": f"Destination ({circuit['id'][:6]}...)",
                        "type": "destination",
                        "status": "online",
                    }
                )

                # Link exit to destination
                links.append(
                    {
                        "source": exit_node_id,
                        "target": dest_id,
                        "type": "exit-to-dest",
                        "circuit_id": circuit["id"],
                    }
                )

        # Update visualization data
        circuit_visualization = {
            "nodes": nodes,
            "links": links,
            "last_updated": datetime.utcnow().isoformat(),
            "circuit_count": len([c for c in circuits if c.get("built", False)]),
            "node_count": len(nodes),
            "connection_status": status,
        }

    except Exception as e:
        logger.exception("Error updating circuit visualization")
        circuit_visualization = {
            "nodes": [],
            "links": [],
            "last_updated": datetime.utcnow().isoformat(),
            "error": str(e),
        }


@tor_bp.route("/visualization")
def get_visualization():
    """Get the current circuit visualization data."""
    update_circuit_visualization()
    return jsonify({"success": True, "visualization": circuit_visualization})


def init_tor_ui(app):
    """Initialize the Tor UI components."""
    # Register blueprints
    app.register_blueprint(tor_bp)

    # Add template filters
    @app.template_filter("format_bytes")
    def format_bytes(value):
        """Format bytes to human-readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if value < 1024.0:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} PB"

    @app.template_filter("format_timestamp")
    def format_timestamp(timestamp):
        """Format a timestamp to a human-readable format."""
        if not timestamp:
            return "Never"
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    @app.context_processor
    def inject_tor_status():
        """Inject Tor status into all templates."""
        return {
            "tor_status": tor_manager.get_connection_status(),
            "tor_network_info": tor_manager.get_network_info(),
        }
