"""
Encryption Benchmark Suite
Measures performance of the multi-layer encryption system.
"""
import asyncio
import time
import json
import os
import stat
import statistics
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
import numpy as np
from .core import EncryptionPipeline, EncryptionResult

@dataclass
class BenchmarkResult:
    """Stores benchmark results for a single test case."""
    name: str
    data_size: int
    num_layers: int
    encrypt_times: List[float] = field(default_factory=list)
    decrypt_times: List[float] = field(default_factory=list)
    encrypt_throughput: List[float] = field(default_factory=list)
    decrypt_throughput: List[float] = field(default_factory=list)
    memory_usage: List[float] = field(default_factory=list)
    
    @property
    def avg_encrypt_time(self) -> float:
        """Average encryption time in seconds."""
        return statistics.mean(self.encrypt_times) if self.encrypt_times else 0.0
    
    @property
    def avg_decrypt_time(self) -> float:
        """Average decryption time in seconds."""
        return statistics.mean(self.decrypt_times) if self.decrypt_times else 0.0
    
    @property
    def avg_encrypt_throughput(self) -> float:
        """Average encryption throughput in MB/s."""
        return statistics.mean(self.encrypt_throughput) if self.encrypt_throughput else 0.0
    
    @property
    def avg_decrypt_throughput(self) -> float:
        """Average decryption throughput in MB/s."""
        return statistics.mean(self.decrypt_throughput) if self.decrypt_throughput else 0.0
    
    @property
    def avg_memory_usage(self) -> float:
        """Average memory usage in MB."""
        return statistics.mean(self.memory_usage) if self.memory_usage else 0.0
    
    def to_dict(self) -> Dict:
        """Convert benchmark results to a dictionary."""
        return {
            'name': self.name,
            'data_size': self.data_size,
            'num_layers': self.num_layers,
            'encrypt_time_avg': self.avg_encrypt_time,
            'decrypt_time_avg': self.avg_decrypt_time,
            'encrypt_throughput_avg': self.avg_encrypt_throughput,
            'decrypt_throughput_avg': self.avg_decrypt_throughput,
            'memory_usage_avg': self.avg_memory_usage,
            'num_runs': len(self.encrypt_times)
        }

class EncryptionBenchmark:
    """Runs benchmarks on the encryption system."""
    
    def __init__(self, output_dir: str = "benchmark_results"):
        """Initialize the benchmark suite."""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results: List[BenchmarkResult] = []
    
    async def _run_single_test(
        self,
        name: str,
        data_size: int,
        num_layers: int,
        num_runs: int = 5,
        password: str = "benchmark_password"
    ) -> BenchmarkResult:
        """Run a single benchmark test case."""
        print(f"\nRunning benchmark: {name}")
        print(f"Data size: {data_size} bytes, Layers: {num_layers}, Runs: {num_runs}")
        
        result = BenchmarkResult(
            name=name,
            data_size=data_size,
            num_layers=num_layers
        )
        
        # Generate random test data
        test_data = os.urandom(data_size)
        
        for run in range(1, num_runs + 1):
            print(f"\nRun {run}/{num_runs}")
            
            # Initialize pipeline for each run to ensure clean state
            pipeline = EncryptionPipeline(num_layers=num_layers)
            
            # Measure encryption
            print("  Encrypting...", end="", flush=True)
            start_time = time.time()
            mem_before = self._get_memory_usage()
            
            try:
                encrypted = await pipeline.process(test_data, password, encrypt=True)
                mem_after = self._get_memory_usage()
                encrypt_time = time.time() - start_time
                
                # Calculate throughput in MB/s
                throughput = (data_size / (1024 * 1024)) / encrypt_time if encrypt_time > 0 else 0
                
                result.encrypt_times.append(encrypt_time)
                result.encrypt_throughput.append(throughput)
                result.memory_usage.append(mem_after - mem_before)
                
                print(f" Done in {encrypt_time:.2f}s ({throughput:.2f} MB/s)")
                
                # Measure decryption
                print("  Decrypting...", end="", flush=True)
                start_time = time.time()
                
                decrypted = await pipeline.process(encrypted.data, password, encrypt=False)
                decrypt_time = time.time() - start_time
                throughput = (data_size / (1024 * 1024)) / decrypt_time if decrypt_time > 0 else 0
                
                result.decrypt_times.append(decrypt_time)
                result.decrypt_throughput.append(throughput)
                
                print(f" Done in {decrypt_time:.2f}s ({throughput:.2f} MB/s)")
                
                # Verify data integrity
                assert test_data == decrypted.data, "Decrypted data does not match original!"
                
            except Exception as e:
                print(f" Error: {str(e)}")
                continue
        
        return result
    
    def _get_memory_usage(self) -> float:
        """Get current process memory usage in MB."""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)  # Convert to MB
    
    async def run_benchmarks(self):
        """Run all benchmark test cases."""
        test_cases = [
            # name, data_size, num_layers, num_runs
            ("Small Data (1KB)", 1024, 100, 5),
            ("Medium Data (1MB)", 1024 * 1024, 100, 5),
            ("Large Data (10MB)", 10 * 1024 * 1024, 100, 3),
            ("Small Data - Many Layers (1KB, 1000 layers)", 1024, 1000, 3),
            ("Medium Data - Few Layers (1MB, 10 layers)", 1024 * 1024, 10, 3),
        ]
        
        print("Starting encryption benchmark suite...")
        print(f"Saving results to: {os.path.abspath(self.output_dir)}")
        
        for name, size, layers, runs in test_cases:
            result = await self._run_single_test(name, size, layers, runs)
            self.results.append(result)
            
            # Save results after each test case
            self.save_results()
    
    def save_results(self, filename: str = None):
        """Save benchmark results to a JSON file."""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"encryption_benchmark_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        results_dict = {
            'timestamp': time.time(),
            'system': self._get_system_info(),
            'results': [r.to_dict() for r in self.results]
        }
        
        with open(filepath, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        print(f"\nResults saved to: {filepath}")
    
    def _get_system_info(self) -> Dict:
        """Get system information for the benchmark."""
        import platform
        import cpuinfo
        import psutil
        
        return {
            'platform': platform.platform(),
            'processor': cpuinfo.get_cpu_info()['brand_raw'],
            'cpu_cores': psutil.cpu_count(logical=False),
            'cpu_threads': psutil.cpu_count(logical=True),
            'total_memory_gb': psutil.virtual_memory().total / (1024 ** 3),
            'python_version': platform.python_version(),
        }
    
    def print_summary(self):
        """Print a summary of benchmark results."""
        if not self.results:
            print("No benchmark results to display.")
            return
        
        print("\n" + "=" * 80)
        print("ENCRYPTION BENCHMARK SUMMARY")
        print("=" * 80)
        
        for result in self.results:
            print(f"\n{result.name}:")
            print(f"  Data size: {result.data_size / 1024:.1f} KB")
            print(f"  Layers: {result.num_layers}")
            print(f"  Avg Encrypt Time: {result.avg_encrypt_time:.3f}s")
            print(f"  Avg Decrypt Time: {result.avg_decrypt_time:.3f}s")
            print(f"  Avg Encrypt Throughput: {result.avg_encrypt_throughput:.2f} MB/s")
            print(f"  Avg Decrypt Throughput: {result.avg_decrypt_throughput:.2f} MB/s")
            print(f"  Avg Memory Usage: {result.avg_memory_usage:.2f} MB")
        
        print("\n" + "=" * 80)


async def main():
    """Run the benchmark suite."""
    benchmark = EncryptionBenchmark()
    
    try:
        await benchmark.run_benchmarks()
        benchmark.print_summary()
        benchmark.save_results()
    except KeyboardInterrupt:
        print("\nBenchmark interrupted. Saving current results...")
        benchmark.print_summary()
        benchmark.save_results("benchmark_interrupted.json")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
