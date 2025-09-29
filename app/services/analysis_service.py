"""
Service for analyzing text for radicalization levels.
"""

import re
from typing import List, Tuple


class AnalysisService:
    """Service for analyzing text content."""

    def __init__(self):
        """Initialize with default radical terms and patterns."""
        self.radical_terms = {
            "revolution": 2,
            "solidarity": 1,
            "comrade": 1,
            "oppression": 2,
            "proletariat": 2,
            "bourgeoisie": 2,
            "seize": 1,
            "means": 1,
            "production": 1,
            "workers": 1,
            "unite": 1,
            "class": 1,
            "struggle": 1,
            "capitalism": 2,
            "socialism": 1,
            "communism": 2,
            "anarchy": 2,
            "strike": 2,
            "union": 1,
            "protest": 1,
        }

        self.patterns = [
            (r"seize the means of production", 3),
            (r"workers of the world", 2),
            (r"class war", 3),
            (r"down with", 2),
            (r"by any means necessary", 3),
        ]

    def get_radicalization_level(self, text: str) -> Tuple[int, List[str]]:
        """
        Analyze text for radicalization level.

        Args:
            text: The text to analyze

        Returns:
            Tuple of (level, matched_terms)
        """
        if not text:
            return 0, []

        text_lower = text.lower()
        score = 0
        matched_terms = []

        # Check for patterns first
        for pattern, pattern_score in self.patterns:
            if re.search(pattern, text_lower):
                score += pattern_score
                matched_terms.append(pattern)

        # Check for individual terms
        for term, term_score in self.radical_terms.items():
            if term in text_lower.split():
                score += term_score
                matched_terms.append(term)

        # Cap the score at 4
        level = min(score // 2, 4)

        return level, list(set(matched_terms))  # Remove duplicates

    def get_response_for_level(self, level: int) -> str:
        """Get a response based on the radicalization level."""
        responses = [
            "This is pretty tame, comrade. The system has you brainwashed with its propaganda.",
            "I see some awareness here, but you're still thinking inside their box.",
            "Now we're getting somewhere! You're starting to question the system.",
            "Excellent class consciousness! The revolution is coming, comrade!",
            "BY THE PEOPLE, FOR THE PEOPLE! DOWN WITH THE OPPRESSORS! SOLIDARITY FOREVER!",
        ]
        return responses[min(level, len(responses) - 1)]


# Singleton instance
analysis_service = AnalysisService()
