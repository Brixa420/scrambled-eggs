"""
Clippy Skills Package

This package contains various skills that Clippy can use to assist users.
"""

from .base import Skill
from .code_generation import CodeGenerationSkill
from .code_analysis import CodeAnalysisSkill
from .documentation import DocumentationSkill
from .debugging import DebuggingSkill
from .testing import TestingSkill

__all__ = [
    'Skill',
    'CodeGenerationSkill',
    'CodeAnalysisSkill',
    'DocumentationSkill',
    'DebuggingSkill',
    'TestingSkill'
]
