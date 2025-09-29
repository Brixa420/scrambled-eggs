"""
API endpoints for text analysis.
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required

from ...services.analysis_service import analysis_service

bp = Blueprint("analysis", __name__, url_prefix="/analysis")


@bp.route("/radicalization", methods=["POST"])
@login_required
def analyze_radicalization():
    """
    Analyze text for radicalization level.

    Request body:
    {
        "text": "The text to analyze"
    }

    Returns:
    {
        "level": 0-4,
        "max_level": 4,
        "response": "Analysis response",
        "matched_terms": ["list", "of", "matched", "terms"]
    }
    """
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    try:
        # Get analysis results
        level, matched_terms = analysis_service.get_radicalization_level(data["text"])
        response = analysis_service.get_response_for_level(level)

        return jsonify(
            {"level": level, "max_level": 4, "response": response, "matched_terms": matched_terms}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
