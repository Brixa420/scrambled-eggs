"""
Service for handling Brixa token operations including price conversion.
"""
import aiohttp
import logging
from decimal import Decimal, ROUND_DOWN
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class BrixaService:
    """Service for Brixa token operations."""
    
    def __init__(self):
        self.base_url = settings.BRIXA_API_URL if hasattr(settings, 'BRIXA_API_URL') else 'https://api.brixa.io/v1'
        self.api_key = settings.BRIXA_API_KEY if hasattr(settings, 'BRIXA_API_KEY') else ''
        
    async def get_brixa_price_usd(self) -> Optional[Decimal]:
        """
        Fetch the current price of 1 Brixa token in USD.
        
        Returns:
            Decimal: Price of 1 Brixa in USD, or None if the price couldn't be fetched.
        """
        try:
            # In a real implementation, this would make an API call to get the current price
            # For now, we'll use a placeholder value or environment variable
            price = getattr(settings, 'BRIXA_PRICE_USD', Decimal('0.10'))  # Default to $0.10 if not set
            return Decimal(str(price)).quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
            
            # Example of how the real implementation might look:
            # async with aiohttp.ClientSession() as session:
            #     headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            #     async with session.get(f'{self.base_url}/price', headers=headers) as response:
            #         if response.status == 200:
            #             data = await response.json()
            #             return Decimal(str(data['price'])).quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
            #         else:
            #             logger.error(f"Failed to fetch Brixa price: {response.status}")
            #             return None
                    
        except Exception as e:
            logger.error(f"Error fetching Brixa price: {str(e)}", exc_info=True)
            return None
    
    async def usd_to_brixa(self, usd_amount: Decimal) -> Decimal:
        """
        Convert USD amount to Brixa tokens.
        
        Args:
            usd_amount: Amount in USD to convert to Brixa.
            
        Returns:
            Decimal: Equivalent amount in Brixa tokens, or 0 if price couldn't be fetched.
        """
        brixa_price = await self.get_brixa_price_usd()
        if not brixa_price or brixa_price <= 0:
            return Decimal('0')
            
        # Calculate Brixa amount with 6 decimal places precision
        brixa_amount = (usd_amount / brixa_price).quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
        return brixa_amount
    
    async def brixa_to_usd(self, brixa_amount: Decimal) -> Decimal:
        """
        Convert Brixa tokens to USD.
        
        Args:
            brixa_amount: Amount in Brixa tokens to convert to USD.
            
        Returns:
            Decimal: Equivalent amount in USD, or 0 if price couldn't be fetched.
        """
        brixa_price = await self.get_brixa_price_usd()
        if not brixa_price:
            return Decimal('0')
            
        # Calculate USD amount with 2 decimal places precision
        usd_amount = (brixa_amount * brixa_price).quantize(Decimal('0.01'), rounding=ROUND_DOWN)
        return usd_amount

# Singleton instance
brixa_service = BrixaService()
