"""
Service for generating and managing rich link previews.
"""
import re
import json
import hashlib
import aiohttp
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from ..models.link_preview import LinkPreview, LinkPreviewStatus
from ..extensions import cache

class LinkPreviewService:
    """Service for handling link preview generation and caching."""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.cache = cache
        self.timeout = 10  # seconds
        self.max_retries = 2
        self.user_agent = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/91.0.4472.124 Safari/537.36'
        )
    
    async def get_preview(self, url: str) -> Optional[Dict]:
        """
        Get a link preview, either from cache or by generating a new one.
        
        Args:
            url: The URL to generate a preview for
            
        Returns:
            Optional[Dict]: The link preview data or None if generation fails
        """
        # Normalize URL
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            return None
            
        # Check cache first
        cache_key = f"link_preview:{normalized_url}"
        cached = await self.cache.get(cache_key)
        if cached:
            return json.loads(cached)
            
        # Check database for existing preview
        preview = self.db.query(LinkPreview).filter_by(url=normalized_url).first()
        
        # If preview exists and is fresh, return it
        if preview and preview.status == LinkPreviewStatus.SUCCESS:
            if preview.updated_at > datetime.utcnow() - timedelta(days=7):
                result = preview.to_dict()
                await self.cache.set(cache_key, json.dumps(result), ex=86400)  # Cache for 1 day
                return result
        
        # Generate new preview
        return await self._generate_preview(normalized_url, cache_key)
    
    async def _generate_preview(self, url: str, cache_key: str) -> Optional[Dict]:
        """Generate a new link preview."""
        # Create or update preview record
        preview = self.db.query(LinkPreview).filter_by(url=url).first()
        if not preview:
            preview = LinkPreview(url=url)
            self.db.add(preview)
        
        preview.status = LinkPreviewStatus.PROCESSING
        preview.attempts += 1
        self.db.commit()
        
        try:
            # Fetch the URL
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': self.user_agent}
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
                        
                    content_type = response.headers.get('content-type', '')
                    if not content_type.startswith('text/html'):
                        raise ValueError(f"Unsupported content type: {content_type}")
                    
                    html = await response.text()
                    data = self._extract_metadata(html, url)
                    
                    # Update preview
                    preview.title = data.get('title')
                    preview.description = data.get('description')
                    preview.image_url = data.get('image')
                    preview.site_name = data.get('site_name')
                    preview.status = LinkPreviewStatus.SUCCESS
                    preview.metadata = data.get('metadata', {})
                    preview.updated_at = datetime.utcnow()
                    
                    self.db.commit()
                    
                    # Cache the result
                    result = preview.to_dict()
                    await self.cache.set(cache_key, json.dumps(result), ex=86400)  # 1 day
                    
                    return result
                    
        except Exception as e:
            logger.error(f"Error generating link preview for {url}: {str(e)}")
            preview.status = LinkPreviewStatus.FAILED
            preview.error = str(e)
            self.db.commit()
            return None
    
    def _extract_metadata(self, html: str, url: str) -> Dict:
        """Extract metadata from HTML content."""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Default metadata
        metadata = {
            'title': '',
            'description': '',
            'image': '',
            'site_name': '',
            'url': url,
            'metadata': {}
        }
        
        # Extract OpenGraph metadata
        for meta in soup.find_all('meta'):
            if 'property' in meta.attrs and meta.attrs['property'].startswith('og:'):
                key = meta.attrs['property'][3:]  # Remove 'og:' prefix
                if key in metadata:
                    metadata[key] = meta.attrs.get('content', '')
                else:
                    metadata['metadata'][key] = meta.attrs.get('content', '')
        
        # Fallback to standard metadata if OpenGraph is not available
        if not metadata['title']:
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.text.strip()
        
        if not metadata['description']:
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and 'content' in meta_desc.attrs:
                metadata['description'] = meta_desc['content'].strip()
        
        # Extract favicon
        icon_link = soup.find('link', rel=re.compile('icon', re.I))
        if icon_link and 'href' in icon_link.attrs:
            metadata['metadata']['favicon'] = self._resolve_url(icon_link['href'], url)
        
        # Extract site name from URL if not found in metadata
        if not metadata['site_name']:
            parsed_url = urlparse(url)
            metadata['site_name'] = parsed_url.netloc.split('.')[-2].capitalize()
        
        return metadata
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL for consistent storage and comparison."""
        if not url or not isinstance(url, str):
            return None
            
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Remove URL fragments and query parameters that don't affect content
        parsed = urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Remove trailing slash for consistency
        clean_url = clean_url.rstrip('/')
        
        return clean_url
    
    def _resolve_url(self, url: str, base_url: str) -> str:
        """Resolve a relative URL against a base URL."""
        if not url or not base_url:
            return url
            
        if url.startswith(('http://', 'https://', '//')):
            return url
            
        base = urlparse(base_url)
        if url.startswith('/'):
            return f"{base.scheme}://{base.netloc}{url}"
            
        return f"{base.scheme}://{base.netloc}{base.path.rsplit('/', 1)[0]}/{url}"
