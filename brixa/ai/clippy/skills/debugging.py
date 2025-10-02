"""
Debugging Skill

This module provides the DebuggingSkill for identifying and fixing code issues.
"""
from typing import Dict, Any, List, Optional
import logging
import traceback
import sys
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from .base import Skill
from dataclasses import dataclass, field

@dataclass
class DebuggingSkill(Skill):
    """Skill for identifying and fixing code issues."""
    
    def __post_init__(self):
        """Initialize the debugging skill."""
        super().__post_init__()
        self.name = "debugging"
        self.description = "Helps identify and fix code issues"
        self.version = "0.1.0"
    
    async def initialize(self, **kwargs) -> None:
        """Initialize the debugging skill."""
        await super().initialize(**kwargs)
        self.logger.info("Debugging skill initialized")
    
    async def debug_code(self, code: str, language: str = "python", input_data: str = "") -> Dict[str, Any]:
        """Debug the given code and return any issues found.
        
        Args:
            code: The source code to debug
            language: The programming language of the code
            input_data: Optional input data for the program
            
        Returns:
            A dictionary containing debugging results and any issues found
        """
        self.logger.info(f"Debugging {language} code")
        
        if language.lower() != "python":
            return {
                "success": False,
                "error": f"Debugging for {language} is not yet supported"
            }
        
        # Create a dictionary to capture the execution context
        local_vars = {}
        global_vars = {"__name__": "__main__"}
        
        # Capture stdout and stderr
        stdout_capture = StringIO()
        stderr_capture = StringIO()
        
        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # First, try to compile the code
                try:
                    compiled_code = compile(code, "<string>", "exec")
                    # If compilation succeeds, execute the code
                    exec(compiled_code, global_vars, local_vars)
                    error_type = None
                    error_message = ""
                    traceback_info = ""
                except Exception as e:
                    error_type = type(e).__name__
                    error_message = str(e)
                    traceback_info = traceback.format_exc()
        except Exception as e:
            error_type = type(e).__name__
            error_message = f"Error during execution: {str(e)}"
            traceback_info = traceback.format_exc()
        
        # Get the captured output
        stdout_output = stdout_capture.getvalue()
        stderr_output = stderr_capture.getvalue()
        
        # Basic syntax check
        syntax_errors = []
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            syntax_errors.append({
                "type": "SyntaxError",
                "message": str(e),
                "lineno": e.lineno,
                "offset": e.offset,
                "text": e.text
            })
        
        # Check for common Python issues
        common_issues = []
        if "import *" in code:
            common_issues.append({
                "type": "Code Smell",
                "message": "Avoid using 'from module import *' as it pollutes the namespace",
                "severity": "warning"
            })
        
        if "except:" in code or "except Exception:" in code:
            common_issues.append({
                "type": "Code Smell",
                "message": "Bare except clauses can hide errors. Catch specific exceptions instead.",
                "severity": "warning"
            })
        
        return {
            "success": error_type is None,
            "language": language,
            "stdout": stdout_output,
            "stderr": stderr_output,
            "error_type": error_type,
            "error_message": error_message,
            "traceback": traceback_info,
            "syntax_errors": syntax_errors,
            "common_issues": common_issues,
            "has_issues": len(syntax_errors) > 0 or len(common_issues) > 0 or error_type is not None
        }
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the debugging skill.
        
        Args:
            context: A dictionary containing the execution context with 'code' and optionally 'language' and 'input_data'
            
        Returns:
            A dictionary containing the debugging results
        """
        code = context.get("code", "")
        language = context.get("language", "python")
        input_data = context.get("input_data", "")
        
        if not code:
            return {
                "success": False,
                "error": "No code provided for debugging"
            }
            
        return await self.debug_code(code, language, input_data)
