"""
API Key Manager for storing and retrieving API keys for various services.
Keys are stored in ~/.kali_tools/api_keys.json
"""
import os
import json
from typing import Optional, Dict


class APIKeyManager:
    """Manages API keys for various reconnaissance tools."""
    
    def __init__(self):
        self.config_dir = os.path.expanduser("~/.kali_tools")
        self.config_file = os.path.join(self.config_dir, "api_keys.json")
        self.keys = self._load_keys()
    
    def _load_keys(self) -> Dict[str, str]:
        """Load API keys from config file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Error loading API keys: {e}")
                return {}
        return {}
    
    def _save_keys(self) -> bool:
        """Save API keys to config file."""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Error saving API keys: {e}")
            return False
    
    def get_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service.
        
        Args:
            service: Service name (e.g., 'shodan', 'hunter', 'virustotal')
        
        Returns:
            API key string or None if not found
        """
        return self.keys.get(service.lower())
    
    def set_key(self, service: str, key: str) -> bool:
        """
        Set API key for a service.
        
        Args:
            service: Service name
            key: API key value
        
        Returns:
            True if saved successfully, False otherwise
        """
        self.keys[service.lower()] = key
        return self._save_keys()
    
    def remove_key(self, service: str) -> bool:
        """
        Remove API key for a service.
        
        Args:
            service: Service name
        
        Returns:
            True if removed successfully, False otherwise
        """
        if service.lower() in self.keys:
            del self.keys[service.lower()]
            return self._save_keys()
        return False
    
    def list_services(self) -> list:
        """Get list of services with configured API keys."""
        return list(self.keys.keys())
    
    def has_key(self, service: str) -> bool:
        """Check if API key exists for a service."""
        return service.lower() in self.keys
    
    def get_all_keys(self) -> Dict[str, str]:
        """Get all API keys (for settings UI)."""
        return self.keys.copy()
    
    @staticmethod
    def get_supported_services() -> Dict[str, str]:
        """
        Get list of supported services with descriptions.
        
        Returns:
            Dictionary mapping service name to description
        """
        return {
            # ── Search Engines (theHarvester, recon-ng, OSINT) ─────────────────
            "google_api_key": "Google Custom Search Engine API key",
            "google_cse_id": "Google Custom Search Engine ID (custom search context)",
            "bing_api_key": "Bing Search API (Microsoft Azure)",
            "baidu_api": "Baidu search integration (theHarvester)",
            "duckduckgo_api": "DuckDuckGo instant answer API",
            "yahoo_api": "Yahoo search API",
            # ── Internet Scanners & Host Lookup ──────────────────────────────
            "shodan": "Shodan - Search engine for Internet-connected devices",
            "censys": "Censys - Internet-wide scan data",
            "binaryedge": "BinaryEdge - Internet scanning platform",
            "fullhunt": "FullHunt - Attack surface database",
            "zoomeye": "ZoomEye - Cyberspace search engine",
            "onyphe": "ONYPHE - Cyber defense search engine",
            "netlas": "Netlas.io - Modern internet scanner (Shodan alternative)",
            "fofa": "FOFA - Internet device search with strong Asia coverage",
            "leakix": "LeakIX - Internet-wide exposed services and vulnerability scanner",
            # ── IP / Network Intelligence ────────────────────────────────────
            "abuseipdb": "AbuseIPDB - IP abuse & reputation database",
            "greynoise": "GreyNoise - Classifies IPs as background noise vs. real threats",
            "ipinfo": "ipinfo.io - IP geolocation, ASN, org, and privacy detection",
            "ipstack": "ipstack - IP geolocation API",
            "ipqualityscore": "IPQualityScore - Fraud scoring, VPN/proxy/Tor detection",
            "maxmind_account_id": "MaxMind GeoIP2 - Account ID for geolocation",
            "maxmind_license_key": "MaxMind GeoIP2 - License key for geolocation",
            # ── Threat Intelligence ──────────────────────────────────────────
            "alienvault": "AlienVault OTX - Free IoC feeds and threat pulse lookups",
            "virustotal": "VirusTotal - File/URL malware scanner",
            "hybrid_analysis": "Hybrid Analysis - Free malware sandbox detonation API",
            "threatfox": "ThreatFox (abuse.ch) - IoC database",
            "malwarebazaar": "MalwareBazaar (abuse.ch) - Malware hash search",
            "urlhaus": "UrlHaus (abuse.ch) - Malicious URL database",
            # ── Breach & Credential Exposure ─────────────────────────────────
            "breachdirectory": "BreachDirectory - Free breach database (500M+ records), alternative to HIBP",
            "dehashed": "Dehashed - Plaintext breach search by email/user/IP/domain",
            "leakcheck": "LeakCheck.io - Credential leak database",
            "xposed": "Xposed - Data breach notification service",
            # ── Domain / DNS / WHOIS ─────────────────────────────────────────
            "securitytrails": "SecurityTrails - DNS and domain intelligence",
            "whoisxml": "WhoisXMLAPI - WHOIS history, reverse IP, DNS, subdomain lookup",
            "passivetotal": "RiskIQ PassiveTotal - Passive DNS history and WHOIS pivoting",
            "dnsdb": "Farsight DNSDB - Largest passive DNS dataset",
            # ── Email / Contact Discovery ────────────────────────────────────
            "hunter": "Hunter.io - Email finder and verifier (OSINT)",
            "emailrep": "EmailRep - Email reputation API",
            "rocketreach": "RocketReach - B2B contact and company intelligence",
            "clearbit": "Clearbit - Company and person intelligence API",
            "knowem": "KnowEm - Social media and username finder",
            # ── Web / URL Analysis ───────────────────────────────────────────
            "urlscan": "urlscan.io - Scan and screenshot any URL",
            "ssllabs_api": "SSL Labs - SSL/TLS certificate analysis",
            "certspotter": "Cert Spotter - Certificate transparency log monitor",
            # ── Code & GitHub Search ─────────────────────────────────────────
            "github": "GitHub - Code repository and user search (PAT)",
            "gitlab": "GitLab - Code repository API token",
            "bitbucket": "Bitbucket - Repository search API",
            # ── Social Media & Content ───────────────────────────────────────
            "x": "X (Twitter) API v2 bearer token - User and keyword OSINT",
            "facebook_api": "Facebook Graph API - User/page search",
            "instagram_api": "Instagram Graph API - User search",
            "linkedin_api": "LinkedIn API - Professional network OSINT",
            "reddit_api": "Reddit API - Subreddit and user search",
            "youtube_api": "YouTube API - Video and channel search",
            # ── General OSINT & Data ─────────────────────────────────────────
            "intelx": "Intelligence X - OSINT search engine and breach data",
            "pastebin": "Pastebin - Paste scraping and search API",
            "google_cse": "Google Custom Search Engine - Programmatic Google dorking",
            # ── Geolocation & Mapping ───────────────────────────────────────
            "opencage": "OpenCage - Geocoding and reverse geocoding API",
            "wigle": "WiGLE - WiFi network geolocation database",
            "mapbox": "Mapbox - Geolocation and mapping services",
            # ── Specialized Tools ────────────────────────────────────────────
            "theharvester_shodan": "theHarvester - Shodan API key",
            "theharvester_bing": "theHarvester - Bing search API key",
            "theharvester_github": "theHarvester - GitHub API token",
            "theharvester_google": "theHarvester - Google API key",
            "recon_ng_default": "recon-ng - Default API keys for modules",
            "maltego_api": "Maltego - API credentials (commercial)",
            "ghostproject_api": "GhostProject - Username validation API",
            "sherlock_enhanced": "Sherlock - Enhanced API keys for faster username search",
            # ── Additional Services ──────────────────────────────────────────
            "axe_api": "Axe.pm - Data breach API",
            "ssrnedb": "SSRnEDB - Search engine integration",
            "criminalip": "Criminal IP - Korean IP threat intelligence",
            "shodan_iocs": "Shodan - Specific IoC (Indicator of Compromise) API",
        }


# Global instance
_api_key_manager = None


def get_api_key_manager() -> APIKeyManager:
    """Get global API key manager instance (singleton pattern)."""
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager
