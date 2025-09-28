"""
Geolocation Utilities
-------------------
Helper functions for geolocation and routing.
"""
from typing import Dict, Tuple, Optional
import random
import math
from ..config import get_config

# Approximate radius of the Earth in kilometers
EARTH_RADIUS_KM = 6371.0

def get_antarctica_coordinates() -> Dict[str, float]:
    """Get coordinates for a random location in Antarctica."""
    # Antarctica is between approximately 60°S and 90°S
    # For more realistic distribution, we'll use a polar projection
    
    # Generate a random angle (0 to 2π)
    angle = random.uniform(0, 2 * math.pi)
    
    # Generate a random distance from the pole (weighted towards the coast)
    # Using square root to get more points near the coast
    distance_from_pole = math.sqrt(random.uniform(0, 1)) * 30  # 0° to 30° from pole
    
    # Convert to latitude (-90° to -60°)
    latitude = -90 + distance_from_pole
    
    # Convert angle to longitude (-180° to 180°)
    longitude = math.degrees(angle)
    if longitude > 180:
        longitude -= 360
    
    return {
        'latitude': round(latitude, 6),
        'longitude': round(longitude, 6),
        'altitude': random.randint(0, 3000)  # Elevation in meters
    }

def calculate_distance(
    lat1: float, 
    lon1: float, 
    lat2: float, 
    lon2: float
) -> float:
    """Calculate the great-circle distance between two points in kilometers."""
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    return EARTH_RADIUS_KM * c

def is_in_international_waters(lat: float, lon: float) -> bool:
    """Check if given coordinates are in international waters."""
    # Antarctica is considered international waters for routing purposes
    return lat <= -60.0  # South of 60°S is the Antarctic Treaty area

def get_routing_info() -> Dict[str, Any]:
    """Get routing information including Antarctica location and proxy details."""
    config = get_config()
    routing_cfg = config.get('antarctica_routing', {})
    
    if routing_cfg.get('enabled', False):
        return {
            'enabled': True,
            'location': routing_cfg.get('coordinates', {
                'latitude': -82.8628,
                'longitude': 135.0
            }),
            'proxies': routing_cfg.get('proxies', []),
            'status': 'active',
            'jurisdiction': 'International Waters (Antarctica)'
        }
    
    return {
        'enabled': False,
        'status': 'inactive',
        'jurisdiction': 'Local Network'
    }

def obfuscate_network_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Obfuscate network metadata to appear as if from Antarctica."""
    config = get_config()
    routing_cfg = config.get('antarctica_routing', {})
    
    if not routing_cfg.get('enabled', False):
        return metadata
    
    # Get Antarctica coordinates
    coords = routing_cfg.get('coordinates', {
        'latitude': -82.8628,
        'longitude': 135.0
    })
    
    # Obfuscate metadata
    obfuscated = metadata.copy()
    
    # Update location data
    if 'location' in obfuscated:
        obfuscated['location'].update({
            'latitude': coords['latitude'],
            'longitude': coords['longitude'],
            'country': 'AQ',  # Antarctica country code
            'region': 'Antarctica',
            'city': 'McMurdo Station',  # Common research station
            'timezone': 'Antarctica/McMurdo',
            'isp': 'International Network',
            'org': 'Scientific Research Network',
            'as': 'AS0000 Research Network',
            'proxy': True,
            'hosting': False
        })
    
    # Update network information
    if 'network' in obfuscated:
        obfuscated['network'].update({
            'ip': '192.168.0.1',  # Generic private IP
            'port': random.randint(40000, 50000),
            'protocol': 'tls',
            'anonymity': 'high',
            'last_check': metadata.get('network', {}).get('last_check', 0)
        })
    
    # Add Antarctica routing headers
    obfuscated['headers'] = obfuscated.get('headers', {})
    obfuscated['headers'].update({
        'X-Routed-Through': 'Antarctica',
        'X-Geo-Location': f"{coords['latitude']},{coords['longitude']}",
        'X-Exit-Node': 'antarctica-proxy-node-01',
        'X-Network-Jurisdiction': 'International Waters'
    })
    
    return obfuscated
