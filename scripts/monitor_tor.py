#!/usr/bin/env python3
"""
Tor monitoring and metrics collection for Scrambled Eggs.
"""
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import stem
import stem.control
from prometheus_client import Counter, Gauge, Histogram, start_http_server

# Configuration
METRICS_PORT = 9091  # Port for Prometheus metrics
LOG_FILE = "tor_monitor.log"
METRICS_FILE = "tor_metrics.json"
METRICS_INTERVAL = 60  # seconds

# Prometheus metrics
TOR_UP = Gauge("tor_up", "Whether Tor is running (1) or not (0)")
TOR_VERSION = Gauge("tor_version", "Tor version", ["version"])
TOR_CIRCUITS = Gauge("tor_circuits", "Number of active circuits")
TOR_STREAMS = Gauge("tor_streams", "Number of active streams")
TOR_BYTES_READ = Counter("tor_bytes_read", "Total bytes read by Tor")
TOR_BYTES_WRITTEN = Counter("tor_bytes_written", "Total bytes written by Tor")
TOR_UPTIME = Gauge("tor_uptime_seconds", "Tor daemon uptime in seconds")
TOR_CIRCUIT_BUILD_TIME = Histogram(
    "tor_circuit_build_time_seconds", "Time to build Tor circuits", ["purpose"]
)
TOR_REQUEST_DURATION = Histogram(
    "tor_request_duration_seconds", "Duration of Tor requests", ["purpose"]
)


class TorMonitor:
    """Monitors Tor metrics and performance."""

    def __init__(self, control_port: int = 9051, password: str = None):
        """Initialize the Tor monitor."""
        self.control_port = control_port
        self.password = password
        self.controller = None
        self.running = False
        self.metrics = {
            "start_time": datetime.utcnow().isoformat(),
            "tor_restarts": 0,
            "circuits_created": 0,
            "circuits_closed": 0,
            "streams_created": 0,
            "streams_closed": 0,
            "errors": 0,
            "alerts": [],
        }

        # Set up logging
        self.logger = self._setup_logging()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger("tor_monitor")
        logger.setLevel(logging.INFO)

        # Create file handler
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(logging.INFO)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def connect_to_tor(self) -> bool:
        """Connect to the Tor control port."""
        try:
            self.controller = stem.control.Controller.from_port(port=self.control_port)

            if self.password:
                self.controller.authenticate(self.password)
            else:
                self.controller.authenticate()

            self.logger.info("Connected to Tor control port")
            return True

        except stem.connection.AuthenticationFailure as e:
            self.logger.error(f"Failed to authenticate with Tor: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to Tor: {e}")
            return False

    def collect_metrics(self) -> Dict[str, Any]:
        """Collect Tor metrics."""
        if not self.controller:
            if not self.connect_to_tor():
                TOR_UP.set(0)
                return {}

        metrics = {}

        try:
            # Basic Tor status
            metrics["is_live"] = self.controller.is_alive()
            TOR_UP.set(1 if metrics["is_live"] else 0)

            # Version info
            version = self.controller.get_version()
            metrics["version"] = version.version_str
            TOR_VERSION.labels(version=version.version_str).set(1)

            # Uptime
            uptime = float(self.controller.get_info("uptime"))
            metrics["uptime_seconds"] = uptime
            TOR_UPTIME.set(uptime)

            # Network status
            metrics["network_live"] = self.controller.get_info("network-liveness") == "up"

            # Circuit metrics
            circuits = list(self.controller.get_circuits())
            metrics["circuit_count"] = len(circuits)
            TOR_CIRCUITS.set(metrics["circuit_count"])

            # Stream metrics
            streams = list(self.controller.get_streams())
            metrics["stream_count"] = len(streams)
            TOR_STREAMS.set(metrics["stream_count"])

            # Bandwidth metrics
            bw_read = int(self.controller.get_info("traffic/read"))
            bw_written = int(self.controller.get_info("traffic/written"))

            metrics["bytes_read"] = bw_read
            metrics["bytes_written"] = bw_written

            TOR_BYTES_READ.inc(bw_read - self.metrics.get("last_bytes_read", 0))
            TOR_BYTES_WRITTEN.inc(bw_written - self.metrics.get("last_bytes_written", 0))

            self.metrics["last_bytes_read"] = bw_read
            self.metrics["last_bytes_written"] = bw_written

            # Circuit build times
            for circuit in circuits:
                if circuit.purpose and circuit.build_flags and "BUILT" in circuit.build_flags:
                    purpose = circuit.purpose.lower()
                    build_time = circuit.time_created - circuit.time_created
                    TOR_CIRCUIT_BUILD_TIME.labels(purpose=purpose).observe(build_time)

            # Save metrics to file
            self._save_metrics(metrics)

            return metrics

        except stem.ControllerError as e:
            self.logger.error(f"Error collecting metrics: {e}")
            TOR_UP.set(0)
            return {}

    def _save_metrics(self, metrics: Dict[str, Any]) -> None:
        """Save metrics to a JSON file."""
        try:
            metrics["timestamp"] = datetime.utcnow().isoformat()
            with open(METRICS_FILE, "w") as f:
                json.dump(metrics, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save metrics: {e}")

    def check_tor_process(self) -> bool:
        """Check if the Tor process is running."""
        for proc in psutil.process_iter(["name"]):
            if "tor" in proc.info["name"].lower():
                return True
        return False

    def run(self):
        """Run the monitoring loop."""
        self.logger.info("Starting Tor monitor...")
        self.running = True

        # Start Prometheus metrics server
        start_http_server(METRICS_PORT)
        self.logger.info(f"Metrics server started on port {METRICS_PORT}")

        # Main monitoring loop
        while self.running:
            try:
                # Check if Tor process is running
                if not self.check_tor_process():
                    self.logger.error("Tor process is not running!")
                    TOR_UP.set(0)
                    time.sleep(10)
                    continue

                # Collect metrics
                metrics = self.collect_metrics()
                if metrics:
                    self.logger.debug(f"Collected metrics: {metrics}")

                # Sleep for the interval
                time.sleep(METRICS_INTERVAL)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(5)

    def stop(self):
        """Stop the monitor."""
        self.logger.info("Stopping Tor monitor...")
        self.running = False
        if self.controller:
            self.controller.close()


def main():
    """Main function."""
    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="Monitor Tor metrics and performance")
    parser.add_argument("--control-port", type=int, default=9051, help="Tor control port")
    parser.add_argument("--password", type=str, help="Tor control port password")
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level",
    )

    args = parser.parse_args()

    # Set up monitor
    monitor = TorMonitor(control_port=args.control_port, password=args.password)

    # Set log level
    monitor.logger.setLevel(getattr(logging, args.log_level))

    try:
        # Run the monitor
        monitor.run()
    except KeyboardInterrupt:
        monitor.logger.info("Shutting down...")
    except Exception as e:
        monitor.logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
