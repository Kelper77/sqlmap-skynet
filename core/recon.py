"""
Target Reconnaissance Module — Pre-scan fingerprinting.
Gathers HTTP headers, tech stack, SSL info, WAF pre-detection,
and response analysis before running sqlmap cycles.
"""
import asyncio
import re
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import aiohttp

from core.debug_logger import logger


class TargetRecon:
    """Pre-scan target reconnaissance and fingerprinting."""

    TECH_SIGNATURES: Dict[str, List[str]] = {
        'PHP': ['x-powered-by: php', 'phpsessid', '.php'],
        'ASP.NET': ['x-powered-by: asp.net', 'x-aspnet-version', '.aspx', '.asp'],
        'Java': ['x-powered-by: servlet', 'jsessionid', '.jsp', '.do'],
        'Python': ['x-powered-by: python', 'x-powered-by: flask', 'x-powered-by: django'],
        'Ruby': ['x-powered-by: phusion', 'x-rack-cache', '_session_id'],
        'Node.js': ['x-powered-by: express', 'connect.sid'],
        'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
        'Joomla': ['joomla', 'com_content', 'option=com_'],
        'Drupal': ['drupal', 'x-drupal-cache', 'x-generator: drupal'],
    }

    SERVER_SIGNATURES: Dict[str, str] = {
        'apache': 'Apache',
        'nginx': 'Nginx',
        'iis': 'Microsoft IIS',
        'litespeed': 'LiteSpeed',
        'caddy': 'Caddy',
        'cloudflare': 'Cloudflare',
        'openresty': 'OpenResty',
    }

    WAF_HEADERS: Dict[str, str] = {
        'cf-ray': 'Cloudflare',
        'x-sucuri-id': 'Sucuri',
        'x-akamai-transformed': 'Akamai',
        'x-cdn': 'CDN/WAF',
        'x-fw-protection': 'Firewall',
        'server: cloudflare': 'Cloudflare',
        'server: akamaighost': 'Akamai',
        'x-amz-cf-id': 'AWS CloudFront',
        'x-amzn-requestid': 'AWS WAF',
        'x-azure-ref': 'Azure WAF',
        'x-iinfo': 'Imperva/Incapsula',
        'x-cdn-geo': 'Incapsula',
    }

    SECURITY_HEADERS = [
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
        'strict-transport-security',
        'content-security-policy',
        'referrer-policy',
        'permissions-policy',
        'x-permitted-cross-domain-policies',
    ]

    def __init__(self):
        self.results: Dict[str, Any] = {}

    async def full_recon(self, url: str, timeout: int = 15) -> Dict[str, Any]:
        """Run full reconnaissance on a target URL."""
        parsed = urlparse(url)
        recon: Dict[str, Any] = {
            'url': url,
            'host': parsed.hostname or '',
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'scheme': parsed.scheme,
            'timestamp': datetime.now().isoformat(),
            'http_info': {},
            'tech_stack': [],
            'server': None,
            'waf_indicators': [],
            'security_headers': {},
            'missing_security_headers': [],
            'ssl_info': {},
            'response_analysis': {},
            'dns_info': {},
            'risk_score': 0,
            'recommendations': [],
        }

        tasks = [
            self._http_fingerprint(url, timeout, recon),
            self._dns_lookup(parsed.hostname or '', recon),
        ]
        if parsed.scheme == 'https':
            tasks.append(self._ssl_check(parsed.hostname or '', recon['port'], recon))

        await asyncio.gather(*tasks, return_exceptions=True)

        self._calculate_risk_score(recon)
        self._generate_recommendations(recon)

        self.results = recon
        logger.info("RECON", f"Recon complete for {url}", {
            'tech': recon['tech_stack'],
            'waf': recon['waf_indicators'],
            'risk': recon['risk_score'],
        })
        return recon

    async def _http_fingerprint(self, url: str, timeout: int, recon: Dict) -> None:
        """Fetch HTTP response and fingerprint target."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    ssl=False,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                                      'Chrome/120.0.0.0 Safari/537.36'
                    }
                ) as resp:
                    recon['http_info'] = {
                        'status_code': resp.status,
                        'reason': resp.reason,
                        'content_type': resp.headers.get('Content-Type', ''),
                        'content_length': resp.headers.get('Content-Length', 'Unknown'),
                        'redirected': str(resp.url) != url,
                        'final_url': str(resp.url),
                    }

                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                    all_headers_str = '\n'.join(
                        f'{k}: {v}' for k, v in headers_lower.items()
                    )

                    body = ''
                    try:
                        body = await resp.text(errors='replace')
                        body = body[:10000]
                    except Exception:
                        pass

                    # Server detection
                    server_header = headers_lower.get('server', '').lower()
                    for sig, name in self.SERVER_SIGNATURES.items():
                        if sig in server_header:
                            recon['server'] = name
                            break
                    if not recon['server'] and server_header:
                        recon['server'] = server_header.title()

                    # Tech stack detection
                    combined = all_headers_str.lower() + '\n' + body.lower()
                    for tech, sigs in self.TECH_SIGNATURES.items():
                        for sig in sigs:
                            if sig.lower() in combined:
                                if tech not in recon['tech_stack']:
                                    recon['tech_stack'].append(tech)
                                break

                    # WAF detection
                    for header_sig, waf_name in self.WAF_HEADERS.items():
                        if ':' in header_sig:
                            key, val = header_sig.split(':', 1)
                            if key.strip() in headers_lower and val.strip().lower() in headers_lower.get(key.strip(), '').lower():
                                if waf_name not in recon['waf_indicators']:
                                    recon['waf_indicators'].append(waf_name)
                        else:
                            if header_sig in headers_lower:
                                if waf_name not in recon['waf_indicators']:
                                    recon['waf_indicators'].append(waf_name)

                    # Security headers audit
                    for sh in self.SECURITY_HEADERS:
                        if sh in headers_lower:
                            recon['security_headers'][sh] = headers_lower[sh]
                        else:
                            recon['missing_security_headers'].append(sh)

                    # Response analysis
                    recon['response_analysis'] = {
                        'has_forms': '<form' in body.lower(),
                        'has_input_fields': '<input' in body.lower(),
                        'has_sql_errors': bool(re.search(
                            r'(sql syntax|mysql|postgresql|oracle|mssql|sqlite|'
                            r'database error|query failed|odbc)', body.lower()
                        )),
                        'has_debug_info': bool(re.search(
                            r'(traceback|stack trace|debug|exception|error in)', body.lower()
                        )),
                        'param_count': len(re.findall(r'[?&](\w+)=', url)),
                        'body_size': len(body),
                    }

        except Exception as e:
            logger.error("RECON", f"HTTP fingerprint failed: {e}")
            recon['http_info'] = {'error': str(e)}

    async def _dns_lookup(self, hostname: str, recon: Dict) -> None:
        """Basic DNS resolution."""
        if not hostname:
            return
        try:
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(hostname, None)
            ips = list(set(addr[4][0] for addr in addrs))
            recon['dns_info'] = {
                'resolved_ips': ips[:5],
                'ipv4': [ip for ip in ips if '.' in ip][:3],
                'ipv6': [ip for ip in ips if ':' in ip][:2],
            }
        except Exception as e:
            recon['dns_info'] = {'error': str(e)}

    async def _ssl_check(self, hostname: str, port: int, recon: Dict) -> None:
        """Basic SSL/TLS certificate info."""
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _get_cert():
                conn = ctx.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=hostname
                )
                conn.settimeout(10)
                conn.connect((hostname, port))
                cert = conn.getpeercert()
                protocol = conn.version()
                conn.close()
                return cert, protocol

            cert, protocol = await loop.run_in_executor(None, _get_cert)

            subject = dict(x[0] for x in cert.get('subject', ()))
            issuer = dict(x[0] for x in cert.get('issuer', ()))

            recon['ssl_info'] = {
                'protocol': protocol,
                'subject': subject.get('commonName', ''),
                'issuer': issuer.get('organizationName', ''),
                'not_before': cert.get('notBefore', ''),
                'not_after': cert.get('notAfter', ''),
                'san': [
                    v for t, v in cert.get('subjectAltName', ())
                    if t == 'DNS'
                ][:5],
            }
        except Exception as e:
            recon['ssl_info'] = {'error': str(e)}

    def _calculate_risk_score(self, recon: Dict) -> None:
        """Calculate a target risk score 0-100 based on findings."""
        score = 0

        ra = recon.get('response_analysis', {})
        if ra.get('has_sql_errors'):
            score += 30
        if ra.get('has_debug_info'):
            score += 15
        if ra.get('has_forms'):
            score += 10
        if ra.get('param_count', 0) > 0:
            score += 10
        if ra.get('param_count', 0) > 3:
            score += 10

        if len(recon.get('missing_security_headers', [])) >= 4:
            score += 10
        if not recon.get('waf_indicators'):
            score += 15

        recon['risk_score'] = min(100, score)

    def _generate_recommendations(self, recon: Dict) -> None:
        """Generate scan recommendations based on recon findings."""
        recs = []

        if recon.get('waf_indicators'):
            wafs = ', '.join(recon['waf_indicators'])
            recs.append(f'WAF detected ({wafs}) — use waf_buster or stealth profile')

        ra = recon.get('response_analysis', {})
        if ra.get('has_sql_errors'):
            recs.append('SQL errors visible in response — error-based injection likely')
        if ra.get('has_debug_info'):
            recs.append('Debug info leaking — may reveal internal paths/queries')
        if ra.get('param_count', 0) == 0:
            recs.append('No URL parameters found — try POST method or crawl for forms')

        if 'PHP' in recon.get('tech_stack', []):
            recs.append('PHP detected — MySQL backend likely, try error-based first')
        if 'ASP.NET' in recon.get('tech_stack', []):
            recs.append('ASP.NET detected — MSSQL backend likely, try stacked queries')
        if 'Java' in recon.get('tech_stack', []):
            recs.append('Java detected — could be Oracle/PostgreSQL, test multiple DBMS')

        if not recon.get('waf_indicators') and recon.get('risk_score', 0) > 40:
            recs.append('No WAF + high risk score — aggressive profile recommended')

        recon['recommendations'] = recs


target_recon = TargetRecon()
