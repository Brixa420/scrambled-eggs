"""
Performance benchmarks for adaptive encryption.
"""
import os
import time
import statistics
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any

import matplotlib.pyplot as plt
import numpy as np
from tqdm import tqdm

from scrambled_eggs.adaptive_encryption import AdaptiveEncryption, Policy

# Test data sizes (in bytes)
DATA_SIZES = [
    16,           # Tiny
    1024,         # 1KB
    1024 * 10,    # 10KB
    1024 * 100,   # 100KB
    1024 * 1024,  # 1MB
    10 * 1024 * 1024,  # 10MB
]

# Test configurations
CONFIGURATIONS = [
    {"name": "Fast", "min_layers": 1, "max_layers": 10, "target_time_ms": 10},
    {"name": "Balanced", "min_layers": 10, "max_layers": 100, "target_time_ms": 50},
    {"name": "Secure", "min_layers": 100, "max_layers": 1000, "target_time_ms": 200},
]


def generate_test_data(size: int) -> bytes:
    """Generate deterministic test data."""
    return os.urandom(size)


def run_benchmark(config: Dict[str, Any], data_size: int, iterations: int = 10) -> Dict[str, Any]:
    """Run a single benchmark configuration."""
    # Initialize encryption with current config
    ae = AdaptiveEncryption(
        min_layers=config["min_layers"],
        max_layers=config["max_layers"],
        target_time_ms=config["target_time_ms"]
    )
    
    # Generate test data
    test_data = generate_test_data(data_size)
    password = b"secure_password_123"
    
    # Warm up
    ciphertext, metadata = ae.encrypt(test_data[:1024], password)
    ae.decrypt(ciphertext, password, metadata)
    
    # Benchmark encryption
    encrypt_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ciphertext, metadata = ae.encrypt(test_data, password)
        encrypt_times.append(time.perf_counter() - start)
    
    # Benchmark decryption
    decrypt_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        decrypted = ae.decrypt(ciphertext, password, metadata)
        decrypt_times.append(time.perf_counter() - start)
    
    # Verify decryption
    assert decrypted == test_data, "Decryption failed!"
    
    # Calculate statistics
    def get_stats(times):
        return {
            "min": min(times) * 1000,  # ms
            "max": max(times) * 1000,  # ms
            "mean": statistics.mean(times) * 1000,  # ms
            "median": statistics.median(times) * 1000,  # ms
            "stddev": statistics.stdev(times) * 1000 if len(times) > 1 else 0,  # ms
            "throughput": (data_size / 1024 / 1024) / statistics.median(times) if statistics.median(times) > 0 else 0  # MB/s
        }
    
    return {
        "config": config,
        "data_size": data_size,
        "iterations": iterations,
        "encrypt": get_stats(encrypt_times),
        "decrypt": get_stats(decrypt_times),
        "final_layers": ae.current_layers,
        "timestamp": datetime.utcnow().isoformat()
    }


def save_results(results: List[Dict], output_dir: str = "benchmark_results"):
    """Save benchmark results to JSON and generate plots."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Save raw results
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_file = output_dir / f"benchmark_{timestamp}.json"
    with open(results_file, 'w') as f:
        json.dump({"results": results}, f, indent=2)
    
    # Generate plots
    plot_results(results, output_dir / f"benchmark_{timestamp}")
    
    return results_file


def plot_results(results: List[Dict], output_prefix: str):
    """Generate plots from benchmark results."""
    # Group by configuration
    configs = {}
    for r in results:
        config_name = r["config"]["name"]
        if config_name not in configs:
            configs[config_name] = []
        configs[config_name].append(r)
    
    # Plot encryption times
    plt.figure(figsize=(12, 6))
    for config_name, config_results in configs.items():
        sizes = [r["data_size"] / 1024 for r in config_results]  # Convert to KB
        times = [r["encrypt"]["mean"] for r in config_results]  # ms
        plt.plot(sizes, times, 'o-', label=config_name)
    
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('Data Size (KB)')
    plt.ylabel('Encryption Time (ms)')
    plt.title('Encryption Performance by Configuration')
    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.savefig(f"{output_prefix}_encryption.png", dpi=300, bbox_inches='tight')
    
    # Plot throughput
    plt.figure(figsize=(12, 6))
    for config_name, config_results in configs.items():
        sizes = [r["data_size"] / 1024 for r in config_results]  # Convert to KB
        throughput = [r["encrypt"]["throughput"] for r in config_results]  # MB/s
        plt.plot(sizes, throughput, 'o-', label=config_name)
    
    plt.xscale('log')
    plt.xlabel('Data Size (KB)')
    plt.ylabel('Throughput (MB/s)')
    plt.title('Encryption Throughput by Configuration')
    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.savefig(f"{output_prefix}_throughput.png", dpi=300, bbox_inches='tight')


def main():
    """Run benchmarks with different configurations."""
    parser = argparse.ArgumentParser(description='Run encryption benchmarks')
    parser.add_argument('--iterations', type=int, default=10, help='Number of iterations per test')
    parser.add_argument('--output', type=str, default='benchmark_results', help='Output directory for results')
    args = parser.parse_args()
    
    results = []
    
    # Run all combinations of configurations and data sizes
    for config in CONFIGURATIONS:
        print(f"\n{'='*40}")
        print(f"Running benchmarks for {config['name']} configuration")
        print(f"Min Layers: {config['min_layers']}, Max Layers: {config['max_layers']}, Target Time: {config['target_time_ms']}ms")
        print("="*40)
        
        for size in tqdm(DATA_SIZES, desc="Data Sizes"):
            result = run_benchmark(config, size, args.iterations)
            results.append(result)
            
            # Print summary
            print(f"\nData Size: {size/1024:.1f} KB")
            print(f"  Encryption: {result['encrypt']['mean']:.2f} ± {result['encrypt']['stddev']:.2f} ms")
            print(f"  Decryption: {result['decrypt']['mean']:.2f} ± {result['decrypt']['stddev']:.2f} ms")
            print(f"  Final Layers: {result['final_layers']}")
    
    # Save results
    results_file = save_results(results, args.output)
    print(f"\nBenchmark complete! Results saved to: {results_file}")


if __name__ == "__main__":
    main()
