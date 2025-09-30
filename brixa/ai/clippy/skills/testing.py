"""
Testing Skill

This module provides the TestingSkill for generating and running tests for code.
"""
from typing import Dict, Any, List, Optional, Tuple
import logging
import importlib
import sys
import os
import re
import tempfile
import unittest
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from .base import Skill
from dataclasses import dataclass, field

@dataclass
class TestingSkill(Skill):
    """Skill for generating and running tests for code."""
    
    def __post_init__(self):
        """Initialize the testing skill."""
        super().__post_init__()
        self.name = "testing"
        self.description = "Generates and runs tests for code"
        self.version = "0.1.0"
    
    async def initialize(self, **kwargs) -> None:
        """Initialize the testing skill."""
        await super().initialize(**kwargs)
        self.logger.info("Testing skill initialized")
    
    async def generate_tests(self, code: str, language: str = "python", framework: str = "unittest") -> Dict[str, Any]:
        """Generate test cases for the given code.
        
        Args:
            code: The source code to generate tests for
            language: The programming language of the code
            framework: The testing framework to use (e.g., 'unittest', 'pytest')
            
        Returns:
            A dictionary containing the generated test code and metadata
        """
        self.logger.info(f"Generating {framework} tests for {language} code")
        
        if language.lower() != "python":
            return {
                "success": False,
                "error": f"Test generation for {language} is not yet supported"
            }
        
        # This is a simplified implementation
        # In a real implementation, this would use a proper test generation tool
        
        # Extract function and class names to generate basic test cases
        test_cases = []
        
        # Function pattern matching
        func_pattern = r'def\s+(\w+)\s*\('
        functions = re.findall(func_pattern, code)
        
        # Class pattern matching
        class_pattern = r'class\s+(\w+)'
        classes = re.findall(class_pattern, code)
        
        # Generate basic test cases for functions
        for func in functions:
            test_case = f'''
    def test_{func}(self):
        """Test the {func} function."""
        # TODO: Add test logic here
        self.skipTest("Test not implemented")'''
            test_cases.append(test_case)
        
        # Generate basic test cases for classes
        for cls in classes:
            test_case = f'''
    def test_{cls}(self):
        """Test the {cls} class."""
        # TODO: Add test logic here
        self.skipTest("Test not implemented")'''
            test_cases.append(test_case)
        
        if not test_cases:
            test_cases = ['''
    def test_example(self):
        """Example test case."""
        self.skipTest("No test cases generated")''']
        
        # Generate the test class
        test_cases_str = "\n".join(test_cases)
        test_code = f'''"""
Test cases for the code.

This file contains automatically generated test cases.
"""

import unittest


class TestGeneratedCode(unittest.TestCase):
    """Test cases for the generated code."""
{test_cases_str}


if __name__ == "__main__":
    unittest.main()
'''
        
        return {
            "success": True,
            "language": language,
            "framework": framework,
            "test_code": test_code,
            "num_test_cases": len(test_cases)
        }
    
    async def run_tests(self, test_code: str, code: str = "", language: str = "python") -> Dict[str, Any]:
        """Run the given test code and return the results.
        
        Args:
            test_code: The test code to run
            code: The original code being tested (if any)
            language: The programming language of the code
            
        Returns:
            A dictionary containing the test results
        """
        if language.lower() != "python":
            return {
                "success": False,
                "error": f"Test execution for {language} is not yet supported"
            }
        
        # Create a temporary directory for the test file
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save the test file
            test_file = Path(temp_dir) / "test_generated.py"
            with open(test_file, "w") as f:
                # If original code is provided, prepend it to the test file
                if code:
                    f.write(f"# Original code\n{code}\n\n")
                f.write(test_code)
            
            # Create a test loader and runner
            test_loader = unittest.TestLoader()
            test_suite = test_loader.discover(temp_dir, pattern="test_*.py")
            
            # Capture the test output
            test_output = StringIO()
            test_runner = unittest.TextTestRunner(stream=test_output, verbosity=2)
            
            # Run the tests
            result = test_runner.run(test_suite)
            
            # Get the test results
            test_results = {
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "expected_failures": len(result.expectedFailures),
                "unexpected_successes": len(result.unexpectedSuccesses),
                "was_successful": result.wasSuccessful(),
                "output": test_output.getvalue()
            }
            
            return {
                "success": True,
                "language": language,
                "results": test_results
            }
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the testing skill.
        
        Args:
            context: A dictionary containing the execution context with 'code' and optionally 'language', 'framework', and 'action'
            
        Returns:
            A dictionary containing the test generation or execution results
        """
        code = context.get("code", "")
        language = context.get("language", "python")
        framework = context.get("framework", "unittest")
        action = context.get("action", "generate")  # 'generate' or 'run'
        
        if not code and action != "run":
            return {
                "success": False,
                "error": "No code provided for test generation"
            }
        
        if action == "run":
            test_code = context.get("test_code", code)
            return await self.run_tests(test_code, code, language)
        else:
            return await self.generate_tests(code, language, framework)
