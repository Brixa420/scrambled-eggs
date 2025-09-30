"""
Clippy Example

This script demonstrates how to use the Clippy AI assistant with its various skills.
"""
import asyncio
import json
from typing import Dict, Any

from brixa.ai.clippy import Clippy

async def run_example():
    """Run the Clippy example."""
    print("Initializing Clippy...")
    
    # Initialize Clippy with default skills
    clippy = Clippy()
    await clippy.initialize()
    
    # Example code to analyze
    example_code = """
import math

def calculate_circle_area(radius: float) -> float:
    """Calculate the area of a circle."""
    return math.pi * (radius ** 2)

class Calculator:
    """A simple calculator class."""
    
    def add(self, a: float, b: float) -> float:
        """Add two numbers."""
        return a + b
    
    def subtract(self, a: float, b: float) -> float:
        """Subtract b from a."""
        return a - b
    """
    
    # Example 1: Code Analysis
    print("\n=== Code Analysis ===")
    analysis = await clippy.execute_skill("code_analysis", {"code": example_code})
    print(f"Code Analysis Results:")
    print(f"- Functions: {analysis.get('functions', [])}")
    print(f"- Classes: {analysis.get('classes', [])}")
    
    # Example 2: Documentation Generation
    print("\n=== Documentation Generation ===")
    docs = await clippy.execute_skill("documentation", {"code": example_code})
    print("Generated Documentation Preview:")
    print(docs.get("documentation", "").split("\n")[0] + "...")
    
    # Example 3: Test Generation
    print("\n=== Test Generation ===")
    tests = await clippy.execute_skill("testing", {"code": example_code})
    test_code = tests.get("test_code", "")
    print(f"Generated {tests.get('num_test_cases', 0)} test cases")
    print("Test Code Preview:")
    print("\n".join(test_code.split("\n")[:10]) + "\n...")
    
    # Example 4: Debugging
    print("\n=== Debugging ===")
    buggy_code = """
def divide(a, b):
    return a / b  # Potential division by zero

result = divide(10, 0)
print(result)
"""
    debug_result = await clippy.execute_skill("debugging", {"code": buggy_code})
    print(f"Debugging found error: {debug_result.get('error_type')}")
    print(f"Error message: {debug_result.get('error_message')}")
    
    # Clean up
    await clippy.cleanup()
    print("\nClippy example completed!")

if __name__ == "__main__":
    asyncio.run(run_example())
