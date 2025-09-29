"""
Web dashboard for Tor metrics visualization.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template, request

from .metrics import MetricsStorage

logger = logging.getLogger(__name__)


class MetricsDashboard:
    """Web dashboard for Tor metrics visualization."""

    def __init__(
        self,
        storage: MetricsStorage,
        host: str = "127.0.0.1",
        port: int = 8050,
        debug: bool = False,
        template_dir: Optional[Path] = None,
        static_dir: Optional[Path] = None,
    ):
        """Initialize the metrics dashboard.

        Args:
            storage: MetricsStorage instance
            host: Host to bind to
            port: Port to listen on
            debug: Enable debug mode
            template_dir: Custom template directory
            static_dir: Custom static files directory
        """
        self.storage = storage
        self.host = host
        self.port = port
        self.debug = debug
        self.server = None

        # Set up Flask app
        self.app = Flask(
            __name__,
            template_folder=str(template_dir) if template_dir else None,
            static_folder=str(static_dir) if static_dir else None,
        )

        # Configure routes
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up Flask routes."""

        @self.app.route("/")
        def index():
            """Render the main dashboard page."""
            return render_template("tor_dashboard.html")

        @self.app.route("/api/metrics/summary")
        def get_metrics_summary():
            """Get metrics summary for the dashboard."""
            try:
                time_window = int(request.args.get("time_window", "300"))
                purpose = request.args.get("purpose")
                isolation_group = request.args.get("isolation_group")

                summary = self.storage.get_metrics_summary(
                    time_window=time_window,
                    purpose=purpose,
                    isolation_group=isolation_group,
                    start_time=datetime.utcnow() - timedelta(hours=24),
                )
                return jsonify(summary)
            except Exception as e:
                logger.error(f"Error getting metrics summary: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/metrics/timeseries")
        def get_metrics_timeseries():
            """Get time series data for charts."""
            try:
                time_window = int(request.args.get("time_window", "300"))
                purpose = request.args.get("purpose")
                isolation_group = request.args.get("isolation_group")
                hours = int(request.args.get("hours", "24"))

                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)

                # Get aggregates for the time period
                aggregates = self.storage.get_metrics_aggregates(
                    time_window=time_window,
                    purpose=purpose,
                    isolation_group=isolation_group,
                    start_time=start_time,
                    end_time=end_time,
                )

                # Format for Chart.js
                labels = []
                request_data = []
                error_rate_data = []
                latency_data = []
                throughput_up_data = []
                throughput_down_data = []

                for agg in sorted(aggregates, key=lambda x: x["timestamp"]):
                    timestamp = datetime.fromisoformat(agg["timestamp"])
                    labels.append(timestamp.strftime("%H:%M"))
                    request_data.append(agg["request_count"])
                    error_rate_data.append(agg.get("error_rate", 0))
                    latency_data.append(
                        agg.get("avg_latency", 0) * 1000 if agg.get("avg_latency") else 0
                    )
                    throughput_up_data.append(agg.get("bytes_sent", 0) / 1024)  # KB
                    throughput_down_data.append(agg.get("bytes_received", 0) / 1024)  # KB

                return jsonify(
                    {
                        "labels": labels,
                        "datasets": {
                            "requests": request_data,
                            "error_rate": error_rate_data,
                            "latency_ms": latency_data,
                            "throughput_up_kb": throughput_up_data,
                            "throughput_down_kb": throughput_down_data,
                        },
                    }
                )
            except Exception as e:
                logger.error(f"Error getting metrics timeseries: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/circuits")
        def get_circuits():
            """Get list of circuits with their metrics."""
            try:
                limit = int(request.args.get("limit", "100"))
                purpose = request.args.get("purpose")
                isolation_group = request.args.get("isolation_group")

                circuits = self.storage.get_circuit_metrics(
                    purpose=purpose, isolation_group=isolation_group, limit=limit
                )
                return jsonify(circuits)
            except Exception as e:
                logger.error(f"Error getting circuits: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/purposes")
        def get_purposes():
            """Get list of all purposes."""
            try:
                purposes = set()
                with self.storage.Session() as session:
                    results = session.query(CircuitMetricsModel.purpose).distinct().all()
                    purposes = {p[0] for p in results if p[0]}
                return jsonify(sorted(list(purposes)))
            except Exception as e:
                logger.error(f"Error getting purposes: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/isolation-groups")
        def get_isolation_groups():
            """Get list of all isolation groups."""
            try:
                groups = set()
                with self.storage.Session() as session:
                    results = session.query(CircuitMetricsModel.isolation_group).distinct().all()
                    groups = {g[0] for g in results if g[0]}
                return jsonify(sorted(list(groups)))
            except Exception as e:
                logger.error(f"Error getting isolation groups: {e}")
                return jsonify({"error": str(e)}), 500

    def start(self) -> None:
        """Start the dashboard server."""
        if self.server is not None:
            logger.warning("Dashboard server is already running")
            return

        logger.info(f"Starting Tor metrics dashboard on http://{self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)

    def stop(self) -> None:
        """Stop the dashboard server."""
        if self.server is not None:
            logger.info("Stopping Tor metrics dashboard")
            # This is a placeholder - in a production environment, you'd want to
            # properly shut down the Flask server
            self.server = None
        else:
            logger.warning("Dashboard server is not running")
