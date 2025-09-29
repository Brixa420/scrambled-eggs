""
Gunicorn configuration file for production.
"""
import multiprocessing
import os

# Server socket
bind = '0.0.0.0:5000'

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'uvicorn.workers.UvicornWorker'
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeouts
timeout = 120
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
capture_output = True

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = 'scrambled-eggs'

# Worker class specific settings
worker_tmp_dir = '/dev/shm'

# Preload application
preload_app = True

# Environment variables
raw_env = [
    'FLASK_APP=app.factory:create_app',
    'FLASK_ENV=production',
]

# Server hooks
def on_starting(server):
    """Run before the server starts."""
    print("Starting Scrambled Eggs server...")

def on_reload(server):
    """Run when the server reloads."""
    print("Reloading Scrambled Eggs server...")

def when_ready(server):
    """Run when the server is ready to accept connections."""
    print("Scrambled Eggs server is ready to accept connections")

def worker_int(worker):
    """Run when a worker is interrupted."""
    print(f"Worker {worker.pid} was interrupted")

def worker_abort(worker):
    """Run when a worker is aborted."""
    print(f"Worker {worker.pid} was aborted")

def worker_exit(server, worker):
    """Run when a worker exits."""
    print(f"Worker {worker.pid} has exited")
