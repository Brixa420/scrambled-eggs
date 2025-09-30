"""
Code Analysis Skill

This module provides the CodeAnalysisSkill for analyzing and understanding code.
"""
from typing import Dict, Any, List, Optional
import logging
import ast
from .base import Skill
from dataclasses import dataclass, field

@dataclass
class CodeAnalysisSkill(Skill):
    """Skill for analyzing and understanding code."""
    
    def __post_init__(self):
        """Initialize the code analysis skill."""
        super().__post_init__()
        self.name = "code_analysis"
        self.description = "Analyzes code to understand its structure and functionality"
        self.version = "0.1.0"
    
    async def initialize(self, **kwargs) -> None:
        """Initialize the code analysis skill."""
        await super().initialize(**kwargs)
        self.logger.info("Code analysis skill initialized")
    
    async def analyze_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze the given code and return information about it.
        
        Args:
            code: The source code to analyze
            language: The programming language of the code
            
        Returns:
            A dictionary containing analysis results
        """
        self.logger.info(f"Analyzing {language} code")
        
        # Basic analysis for Python code
        if language.lower() == "python":
            try:
                # Parse the code into an AST
                tree = ast.parse(code)
                
                # Count functions and classes
                functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
                classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
                imports = [node for node in ast.walk(tree) if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom)]
                
                return {
                    "success": True,
                    "language": language,
                    "num_functions": len(functions),
                    "num_classes": len(classes),
                    "num_imports": len(imports),
                    "functions": [f.name for f in functions],
                    "classes": [c.name for c in classes],
                    "imports": [self._format_import(i) for i in imports]
                }
            except SyntaxError as e:
                return {
                    "success": False,
                    "error": f"Syntax error in code: {str(e)}",
                    "language": language
                }
        else:
            # For non-Python code, return basic info
            return {
                "success": True,
                "language": language,
                "code_length": len(code),
                "lines": len(code.splitlines())
            }
    
    def _format_import(self, node):
        """Format an import statement for display."""
        if isinstance(node, ast.Import):
            return f"import {', '.join(alias.name for alias in node.names)}"
        elif isinstance(node, ast.ImportFrom):
            return f"from {node.module} import {', '.join(alias.name for alias in node.names)}"
        return str(node)
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the code analysis skill.
        
        Args:
            context: A dictionary containing the execution context with 'code' and optionally 'language'
            
        Returns:
            A dictionary containing the analysis results
        """
        code = context.get("code", "")
        language = context.get("language", "python")
        
        if not code:
            return {
                "success": False,
                "error": "No code provided for analysis"
            }
            
        return await self.analyze_code(code, language)
