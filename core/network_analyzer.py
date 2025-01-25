# network_analyzer.py
import subprocess
import re
import logging
from typing import Dict, List, Tuple, Optional
import platform
import json

class NetworkAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger("network_analyzer_log")

    def analyze_network(self, ssid: str) -> Optional[Dict[str, any]]:
        self.logger.info(f"Analyzing network: {ssid}")
        if platform.system() == "Linux":
            return self._analyze_linux(ssid)
        elif platform.system() == "Darwin":  # macOS
            return self._analyze_macos(ssid)
        elif platform.system() == "Windows":
            return self._analyze_windows(ssid)
        else:
            self.logger.error(f"Unsupported operating system: {platform.system()}")
            return None

    def _analyze_linux(self, ssid: str) -> Optional[Dict[str, any]]:
        try:
            result = subprocess.run(['iwlist', 'scanning'], capture_output=True, text=True, check=True)
            networks = re.findall(r'ESSID:"(.*?)"\s*\n.*?Encryption key:(.*?)\n.*?Quality=(.*?)/', result.stdout, re.DOTALL)
            for network in networks:
                if network[0] == ssid:
                    encryption = "WPA2" if "on" in network[1] else "Open"
                    quality = int(network[2].split('/')[0])
                    return {
                        'ssid': ssid,
                        'encryption': encryption,
                        'signal_quality': quality
                    }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running iwlist: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing network on Linux: {e}")
        return None

    def _analyze_macos(self, ssid: str) -> Optional[Dict[str, any]]:
        try:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], capture_output=True, text=True, check=True)
            networks = re.findall(r'(.*?)\s+(.*?)\s+(.*?)\s+', result.stdout)
            for network in networks:
                if network[0].strip() == ssid:
                    encryption = "WPA2" if "WPA2" in network[2] else "Open"
                    quality = int(network[1])
                    return {
                        'ssid': ssid,
                        'encryption': encryption,
                        'signal_quality': quality
                    }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running airport command: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing network on macOS: {e}")
        return None

    def _analyze_windows(self, ssid: str) -> Optional[Dict[str, any]]:
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], capture_output=True, text=True, check=True)
            networks = re.findall(r'SSID\s+\d+\s+:\s+(.*?)\n.*?Authentication\s+:\s+(.*?)\n.*?Signal\s+:\s+(\d+)%', result.stdout, re.DOTALL)
            for network in networks:
                if network[0].strip() == ssid:
                    encryption = "WPA2" if "WPA2" in network[1] else "Open"
                    quality = int(network[2])
                    return {
                        'ssid': ssid,
                        'encryption': encryption,
                        'signal_quality': quality
                    }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running netsh command: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing network on Windows: {e}")
        return None

    def get_recommendations(self, analysis: Dict[str, any]) -> List[str]:
        recommendations = []
        if analysis['encryption'] == "Open":
            recommendations.append("This network is unsecured. Avoid transmitting sensitive information.")
        elif analysis['encryption'] != "WPA2":
            recommendations.append("This network uses outdated encryption. Recommend upgrading to WPA2.")
        
        if analysis['signal_quality'] < 50:
            recommendations.append("Weak signal strength. Consider moving closer to the access point.")
        
        return recommendations

    def get_all_networks(self) -> List[Dict[str, any]]:
        if platform.system() == "Linux":
            return self._get_all_networks_linux()
        elif platform.system() == "Darwin":  # macOS
            return self._get_all_networks_macos()
        elif platform.system() == "Windows":
            return self._get_all_networks_windows()
        else:
            self.logger.error(f"Unsupported operating system: {platform.system()}")
            return []

    def _get_all_networks_linux(self) -> List[Dict[str, any]]:
        networks = []
        try:
            result = subprocess.run(['iwlist', 'scanning'], capture_output=True, text=True, check=True)
            network_data = re.findall(r'ESSID:"(.*?)"\s*\n.*?Encryption key:(.*?)\n.*?Quality=(.*?)/', result.stdout, re.DOTALL)
            for network in network_data:
                ssid = network[0]
                encryption = "WPA2" if "on" in network[1] else "Open"
                quality = int(network[2].split('/')[0])
                networks.append({
                    'ssid': ssid,
                    'encryption': encryption,
                    'signal_quality': quality
                })
        except Exception as e:
            self.logger.error(f"Error getting all networks on Linux: {e}")
        return networks

    def _get_all_networks_macos(self) -> List[Dict[str, any]]:
        networks = []
        try:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], capture_output=True, text=True, check=True)
            network_data = re.findall(r'(.*?)\s+(.*?)\s+(.*?)\s+', result.stdout)
            for network in network_data:
                ssid = network[0].strip()
                encryption = "WPA2" if "WPA2" in network[2] else "Open"
                quality = int(network[1])
                networks.append({
                    'ssid': ssid,
                    'encryption': encryption,
                    'signal_quality': quality
                })
        except Exception as e:
            self.logger.error(f"Error getting all networks on macOS: {e}")
        return networks

    def _get_all_networks_windows(self) -> List[Dict[str, any]]:
        networks = []
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], capture_output=True, text=True, check=True)
            network_data = re.findall(r'SSID\s+\d+\s+:\s+(.*?)\n.*?Authentication\s+:\s+(.*?)\n.*?Signal\s+:\s+(\d+)%', result.stdout, re.DOTALL)
            for network in network_data:
                ssid = network[0].strip()
                encryption = "WPA2" if "WPA2" in network[1] else "Open"
                quality = int(network[2])
                networks.append({
                    'ssid': ssid,
                    'encryption': encryption,
                    'signal_quality': quality
                })
        except Exception as e:
            self.logger.error(f"Error getting all networks on Windows: {e}")
        return networks

