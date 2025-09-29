import logging
from typing import Dict, Optional, Tuple
import openai
import os
from datetime import datetime

from app.core.config import settings
from app.models.ban_appeal import BanAppeal, BanAppealStatus

logger = logging.getLogger(__name__)

class BanAppealService:
    """
    Service for handling ban appeals with AI moderation.
    """
    
    def __init__(self):
        self.openai_api_key = settings.OPENAI_API_KEY
        openai.api_key = self.openai_api_key
        
        # Configure AI model
        self.ai_model = "gpt-4"  # or another suitable model
        self.ai_temperature = 0.7
        
    async def analyze_appeal(
        self, 
        ban_reason: str, 
        appeal_text: str,
        user_history: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze a ban appeal using AI.
        
        Args:
            ban_reason: The reason for the original ban
            appeal_text: User's appeal text
            user_history: Optional user history (previous bans, reports, etc.)
            
        Returns:
            Dict containing analysis results and recommendation
        """
        try:
            # Prepare the prompt for the AI
            prompt = self._create_prompt(ban_reason, appeal_text, user_history)
            
            # Call the OpenAI API
            response = await openai.ChatCompletion.acreate(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an AI moderator analyzing ban appeals. "
                                     "Be fair, objective, and consider the user's perspective."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.ai_temperature,
                max_tokens=500
            )
            
            # Parse the AI's response
            analysis = self._parse_ai_response(response.choices[0].message.content)
            
            return {
                'status': 'success',
                'analysis': analysis,
                'recommendation': analysis.get('recommendation', 'further_review_needed'),
                'confidence': analysis.get('confidence', 0.7),
                'explanation': analysis.get('explanation', '')
            }
            
        except Exception as e:
            logger.error(f"Error analyzing ban appeal: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'recommendation': 'further_review_needed',
                'confidence': 0.0
            }
    
    def _create_prompt(self, ban_reason: str, appeal_text: str, user_history: Dict = None) -> str:
        """Create a prompt for the AI based on the ban appeal."""
        prompt = f"""
        Analyze this ban appeal and provide a recommendation.
        
        BAN REASON:
        {ban_reason}
        
        USER'S APPEAL:
        {appeal_text}
        """
        
        if user_history:
            prompt += "\n\nUSER HISTORY:\n"
            if user_history.get('previous_bans'):
                prompt += f"- Previous bans: {user_history['previous_bans']}\n"
            if user_history.get('warning_count', 0) > 0:
                prompt += f"- Warnings: {user_history['warning_count']} previous warnings\n"
            if user_history.get('account_age_days'):
                prompt += f"- Account age: {user_history['account_age_days']} days\n"
        
        prompt += """
        
        Please analyze this appeal and provide:
        1. A recommendation (approve, reject, or needs_further_review)
        2. A confidence score (0.0 to 1.0)
        3. A brief explanation of your reasoning
        4. Any suggested conditions for lifting the ban (if applicable)
        
        Format your response as JSON with these keys:
        {
            "recommendation": "approve" | "reject" | "needs_further_review",
            "confidence": 0.0-1.0,
            "explanation": "Your explanation here",
            "suggested_conditions": ["condition1", "condition2"]
        }
        """
        
        return prompt
    
    def _parse_ai_response(self, ai_text: str) -> Dict:
        """Parse the AI's response into a structured format."""
        try:
            # Try to extract JSON from the response
            import json
            import re
            
            # Find JSON in the response
            json_match = re.search(r'\{.*\}', ai_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            
            # If no JSON found, return a default response
            return {
                'recommendation': 'needs_further_review',
                'confidence': 0.5,
                'explanation': 'Unable to parse AI response',
                'suggested_conditions': []
            }
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
            return {
                'recommendation': 'needs_further_review',
                'confidence': 0.5,
                'explanation': f'Error parsing AI response: {str(e)}',
                'suggested_conditions': []
            }
    
    async def process_appeal(self, appeal: BanAppeal) -> Tuple[BanAppealStatus, str]:
        """
        Process a ban appeal using AI moderation.
        
        Returns:
            Tuple of (status, message)
        """
        try:
            # Get user history for context
            user_history = await self._get_user_history(appeal.user_id)
            
            # Analyze the appeal
            analysis = await self.analyze_appeal(
                ban_reason=appeal.ban_reason,
                appeal_text=appeal.appeal_text,
                user_history=user_history
            )
            
            # Update the appeal with AI analysis
            appeal.ai_analysis = analysis
            
            # Determine the status based on AI recommendation
            if analysis['recommendation'] == 'approve' and analysis['confidence'] >= 0.8:
                status = BanAppealStatus.APPROVED
                message = "Your appeal has been approved. The ban has been lifted."
            elif analysis['recommendation'] == 'reject' and analysis['confidence'] >= 0.8:
                status = BanAppealStatus.REJECTED
                message = "Your appeal has been denied. The ban remains in place."
            else:
                status = BanAppealStatus.FURTHER_REVIEW_NEEDED
                message = "Your appeal requires further review by our moderation team."
            
            return status, message
            
        except Exception as e:
            logger.error(f"Error processing ban appeal: {str(e)}", exc_info=True)
            return BanAppealStatus.FURTHER_REVIEW_NEEDED, "An error occurred while processing your appeal."
    
    async def _get_user_history(self, user_id: int) -> Dict:
        """Get relevant user history for ban appeal analysis."""
        # In a real implementation, this would query the database
        # For now, return a placeholder
        return {
            'previous_bans': 0,
            'warning_count': 0,
            'account_age_days': 365
        }

# Singleton instance
ban_appeal_service = BanAppealService()
