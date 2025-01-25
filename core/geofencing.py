# geofencing.py
from geopy.distance import distance
from geopy.geocoders import Nominatim
import requests
import json
from typing import Tuple, List
import logging

class Geofence:
    def __init__(self, center_lat: float, center_lon: float, radius: float):
        self.center = (center_lat, center_lon)
        self.radius = radius
        self.geolocator = Nominatim(user_agent="wifi_retriever")
        self.logger = logging.getLogger("geofence_log")

    def is_within_fence(self, lat: float, lon: float) -> bool:
        point = (lat, lon)
        dist = distance(self.center, point).km
        within = dist <= self.radius
        self.logger.info(f"Distance to center: {dist:.2f}km. Within fence: {within}")
        return within

    def get_current_location(self) -> Tuple[float, float]:
        try:
            response = requests.get('https://ipapi.co/json/')
            data = response.json()
            lat, lon = data['latitude'], data['longitude']
            self.logger.info(f"Current location: {lat}, {lon}")
            return lat, lon
        except Exception as e:
            self.logger.error(f"Error getting location: {str(e)}")
            raise

    def get_address(self, lat: float, lon: float) -> str:
        try:
            location = self.geolocator.reverse(f"{lat}, {lon}")
            return location.address
        except Exception as e:
            self.logger.error(f"Error getting address: {str(e)}")
            return "Unknown"

    def set_center(self, lat: float, lon: float):
        self.center = (lat, lon)
        self.logger.info(f"New center set: {lat}, {lon}")

    def set_radius(self, radius: float):
        self.radius = radius
        self.logger.info(f"New radius set: {radius}km")

    def get_fence_info(self) -> dict:
        return {
            "center": self.center,
            "radius": self.radius,
            "center_address": self.get_address(*self.center)
        }

