"""
Anonymity Layer — IP masking, fingerprint randomization, and Tor integration.
Ensures full anonymity during scanning operations.
"""
import os
import random
import subprocess
from typing import Dict, Optional

from core.debug_logger import logger


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

ACCEPT_HEADERS = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    '*/*',
]

ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.8',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9,fr;q=0.5',
    'en,en-US;q=0.9,de;q=0.7',
]


class AnonymityManager:
    """Manage anonymity features: Tor, random UA, fingerprint randomization."""

    TOR_SOCKS_PROXY = 'socks5://127.0.0.1:9050'
    TOR_HTTP_PROXY = 'http://127.0.0.1:8118'

    def __init__(self):
        self.tor_available = False
        self.tor_enabled = False
        self._check_tor()

    def _check_tor(self) -> None:
        """Check if Tor is available on the system."""
        try:
            result = subprocess.run(
                ['tor', '--version'],
                capture_output=True, timeout=5
            )
            self.tor_available = result.returncode == 0
        except Exception:
            self.tor_available = False

        if self.tor_available:
            logger.info("ANON", "Tor detected on system")
        else:
            logger.info("ANON", "Tor not detected — anonymity via header randomization only")

    def enable_tor(self) -> bool:
        """Enable Tor for anonymity."""
        if not self.tor_available:
            logger.warning("ANON", "Cannot enable Tor — not installed")
            return False
        self.tor_enabled = True
        logger.info("ANON", "Tor enabled — routing through SOCKS5 proxy")
        return True

    def disable_tor(self) -> None:
        self.tor_enabled = False

    def get_proxy(self) -> Optional[str]:
        """Get the current proxy URL or None."""
        if self.tor_enabled and self.tor_available:
            return self.TOR_SOCKS_PROXY
        return None

    def get_random_headers(self) -> Dict[str, str]:
        """Generate randomized HTTP headers to avoid fingerprinting."""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': random.choice(ACCEPT_HEADERS),
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': random.choice(['keep-alive', 'close']),
            'Cache-Control': random.choice(['no-cache', 'max-age=0', 'no-store']),
            'DNT': '1',
            'Sec-Fetch-Dest': random.choice(['document', 'empty']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Upgrade-Insecure-Requests': '1',
        }
        # Randomly omit some optional headers
        optional = ['DNT', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site',
                     'Upgrade-Insecure-Requests', 'Cache-Control']
        for h in optional:
            if random.random() < 0.3:
                headers.pop(h, None)

        return headers

    def get_sqlmap_anon_args(self) -> list:
        """Get sqlmap CLI args for anonymity."""
        args = [
            '--random-agent',
        ]
        if self.tor_enabled and self.tor_available:
            args.extend([
                '--tor',
                '--tor-type=SOCKS5',
                '--tor-port=9050',
                '--check-tor',
            ])
        return args

    def get_status(self) -> Dict[str, bool]:
        return {
            'tor_available': self.tor_available,
            'tor_enabled': self.tor_enabled,
            'header_randomization': True,
            'fingerprint_protection': True,
        }


anonymity = AnonymityManager()
