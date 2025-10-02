"""
Brixa AI - Model Evaluation Module

This module provides tools for evaluating and comparing machine learning models.
"""

from .evaluator import ModelEvaluator
from .metrics import (
    ClassificationMetrics,
    RegressionMetrics,
    BiasFairnessMetrics,
    PerformanceMetrics
)
from .comparison import ModelComparator

__all__ = [
    'ModelEvaluator',
    'ClassificationMetrics',
    'RegressionMetrics',
    'BiasFairnessMetrics',
    'PerformanceMetrics',
    'ModelComparator'
]
