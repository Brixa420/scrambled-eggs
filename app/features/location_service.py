"""
Location Service for Brixa

Handles location services including Antarctica-specific features and geofencing.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import pytz
from geopy.distance import geodesic
from geopy.geocoders import Nominatim


@dataclass
class Location:
    """Represents a geographic location with metadata."""

    latitude: float
    longitude: float
    name: str = ""
    timestamp: datetime = None
    accuracy: float = 0.0

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(pytz.utc)

    @property
    def coordinates(self) -> Tuple[float, float]:
        """Return latitude and longitude as a tuple."""
        return (self.latitude, self.longitude)

    def distance_to(self, other: "Location") -> float:
        """Calculate distance to another location in kilometers."""
        return geodesic(self.coordinates, other.coordinates).kilometers

    def is_in_antarctica(self) -> bool:
        """Check if the location is within Antarctica."""
        # Antarctica bounding box (approximate)
        ant_bounds = {"min_lat": -90.0, "max_lat": -60.0, "min_lon": -180.0, "max_lon": 180.0}
        return (
            ant_bounds["min_lat"] <= self.latitude <= ant_bounds["max_lat"]
            and ant_bounds["min_lon"] <= self.longitude <= ant_bounds["max_lon"]
        )


class LocationService:
    """Manages location-related functionality for Brixa."""

    # McMurdo Station, Antarctica as reference point
    MCMURDO_STATION = (-77.85, 166.67)

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.geolocator = Nominatim(user_agent="brixa_location")
        self.current_location: Optional[Location] = None
        self.last_updated: Optional[datetime] = None
        self.antarctic_bases = self._load_antarctic_bases()

    def _load_antarctic_bases(self) -> Dict[str, Dict[str, Any]]:
        """Load known Antarctic research stations and bases."""
        return {
            "mcmurdo": {
                "name": "McMurdo Station",
                "country": "USA",
                "location": (-77.85, 166.67),
                "population": 1000,
                "description": "Largest research station in Antarctica",
                "timezone": "Antarctica/McMurdo",
            },
            "amundsen_scott": {
                "name": "Amundsen-Scott South Pole Station",
                "country": "USA",
                "location": (-90.0, 0.0),
                "population": 150,
                "description": "Research station at the geographic South Pole",
                "timezone": "Antarctica/South_Pole",
            },
            "vostok": {
                "name": "Vostok Station",
                "country": "Russia",
                "location": (-78.46, 106.83),
                "population": 25,
                "description": "Russian research station near the Southern Pole of Cold",
                "timezone": "Antarctica/Vostok",
            },
            "concordia": {
                "name": "Concordia Research Station",
                "country": "France/Italy",
                "location": (-75.10, 123.35),
                "population": 60,
                "description": "French-Italian research facility on the Antarctic Plateau",
                "timezone": "Antarctica/Davis",  # Closest timezone
            },
            "palmer": {
                "name": "Palmer Station",
                "country": "USA",
                "location": (-64.77, -64.05),
                "population": 44,
                "description": "US research station on Anvers Island",
                "timezone": "Antarctica/Palmer",
            },
        }

    def get_nearest_antarctic_base(self, location: Location) -> Dict[str, Any]:
        """Find the nearest Antarctic research base to the given location."""
        if not location.is_in_antarctica():
            return {}

        nearest = None
        min_distance = float("inf")

        for base_id, base_info in self.antarctic_bases.items():
            base_loc = Location(*base_info["location"])
            distance = location.distance_to(base_loc)

            if distance < min_distance:
                min_distance = distance
                nearest = base_info.copy()
                nearest["distance_km"] = round(distance, 2)

        return nearest

    def get_location_name(self, latitude: float, longitude: float) -> str:
        """Get a human-readable name for the given coordinates."""
        try:
            location = self.geolocator.reverse(f"{latitude}, {longitude}", exactly_one=True)
            return location.address if location else f"{latitude:.4f}°N, {longitude:.4f}°E"
        except Exception as e:
            self.logger.warning(f"Failed to get location name: {e}")
            return f"{latitude:.4f}°N, {longitude:.4f}°E"

    def update_location(self, latitude: float, longitude: float, accuracy: float = 0.0) -> Location:
        """Update the current location with new coordinates."""
        location_name = self.get_location_name(latitude, longitude)
        self.current_location = Location(
            latitude=latitude,
            longitude=longitude,
            name=location_name,
            accuracy=accuracy,
            timestamp=datetime.now(pytz.utc),
        )
        self.last_updated = datetime.now(pytz.utc)
        return self.current_location

    def get_weather_conditions(self, location: Location) -> Dict[str, Any]:
        """Get weather conditions for the given location (stub for actual API integration)."""
        if not location.is_in_antarctica():
            return {}

        # In a real implementation, this would call a weather API
        return {
            "temperature": -20.0,  # in Celsius
            "conditions": "Clear",
            "wind_speed": 15.0,  # in km/h
            "wind_direction": "SE",
            "sunrise": "Sun does not rise" if self._is_polar_night(location) else "00:00",
            "sunset": "Sun does not set" if self._is_midnight_sun(location) else "00:00",
        }

    def _is_polar_night(self, location: Location) -> bool:
        """Check if it's polar night at the given location."""
        # Simplified check - in a real app, use proper astronomical calculations
        return location.latitude < -66.5 and datetime.now().month in [6, 7]

    def _is_midnight_sun(self, location: Location) -> bool:
        """Check if it's midnight sun at the given location."""
        # Simplified check - in a real app, use proper astronomical calculations
        return location.latitude < -66.5 and datetime.now().month in [12, 1]

    def get_antarctic_time(self) -> Dict[str, str]:
        """Get current times for major Antarctic timezones."""
        timezones = {
            "McMurdo": "Antarctica/McMurdo",
            "South Pole": "Antarctica/South_Pole",
            "Palmer": "Antarctica/Palmer",
            "Rothera": "Antarctica/Rothera",
            "Mawson": "Antarctica/Mawson",
            "Davis": "Antarctica/Davis",
            "Casey": "Antarctica/Casey",
            "DumontDUrville": "Antarctica/DumontDUrville",
            "Syowa": "Antarctica/Syowa",
            "Maitri": "Antarctica/Mawson",  # Uses same as Mawson
            "Vostok": "Antarctica/Vostok",
            "Troll": "Antarctica/Troll",
            "Concordia": "Antarctica/Davis",  # Uses same as Davis
        }

        times = {}
        for name, tz_name in timezones.items():
            try:
                tz = pytz.timezone(tz_name)
                times[name] = datetime.now(tz).strftime("%H:%M %Z")
            except Exception as e:
                self.logger.warning(f"Failed to get time for {tz_name}: {e}")
                times[name] = "N/A"

        return times
