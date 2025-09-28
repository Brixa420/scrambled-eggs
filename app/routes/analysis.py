"""
Routes for text analysis features.
"""
from flask import Blueprint, render_template
from flask_login import login_required

bp = Blueprint('analysis', __name__)

@bp.route('/analysis')
@login_required
def analysis_page():
    """Render the text analysis page."""
    return render_template('analysis.html')
