"""
Script to run model registry tests.
"""
import sys
import pytest

def main():
    # Add the project root to the Python path
    import os
    sys.path.insert(0, os.path.abspath('.'))
    
    # Run the tests with verbose output
    test_file = os.path.join('tests', 'test_model_registry.py')
    return pytest.main([test_file, '-v'])

if __name__ == "__main__":
    sys.exit(main())
