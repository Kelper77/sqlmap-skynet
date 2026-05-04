"""
Scan Profiles System — Pre-built scan strategies for different scenarios.
Each profile auto-tunes tamper scripts, delay, threads, level, risk, and technique.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class ScanProfile:
    name: str
    description: str
    level: int
    risk: int
    threads: int
    delay: int
    timeout: int
    retries: int
    technique: str
    tamper: str
    max_cycles: int
    random_agent: bool
    tor_recommended: bool
    options: Dict[str, Any] = field(default_factory=dict)


SCAN_PROFILES: Dict[str, ScanProfile] = {
    'stealth': ScanProfile(
        name='Stealth',
        description='Low-noise scan. Minimal requests, high delay, single thread. '
                    'Best for targets with aggressive rate limiting or IDS.',
        level=1,
        risk=1,
        threads=1,
        delay=8,
        timeout=30,
        retries=5,
        technique='T',
        tamper='space2comment,randomcase',
        max_cycles=15,
        random_agent=True,
        tor_recommended=True,
        options={
            'safe_url_check': True,
            'skip_waf': False,
            'crawl_depth': 0,
            'time_sec': 10,
        }
    ),
    'balanced': ScanProfile(
        name='Balanced',
        description='Default balanced scan. Good mix of speed and stealth. '
                    'Suitable for most targets.',
        level=2,
        risk=2,
        threads=3,
        delay=2,
        timeout=30,
        retries=3,
        technique='BEUST',
        tamper='space2comment,between,randomcase',
        max_cycles=30,
        random_agent=True,
        tor_recommended=False,
        options={
            'safe_url_check': False,
            'skip_waf': False,
            'crawl_depth': 1,
        }
    ),
    'aggressive': ScanProfile(
        name='Aggressive',
        description='Full-power scan. All techniques, high level/risk, multi-threaded. '
                    'Best for targets you own or have explicit permission to test hard.',
        level=5,
        risk=3,
        threads=8,
        delay=0,
        timeout=15,
        retries=2,
        technique='BEUSTQ',
        tamper='space2comment,between,randomcase,charencode,percentage',
        max_cycles=50,
        random_agent=True,
        tor_recommended=False,
        options={
            'safe_url_check': False,
            'skip_waf': False,
            'crawl_depth': 3,
            'forms': True,
        }
    ),
    'deep_recon': ScanProfile(
        name='Deep Recon',
        description='Maximum enumeration depth. Focuses on discovering all databases, '
                    'tables, columns, and dumping high-value data. Slower but thorough.',
        level=5,
        risk=3,
        threads=4,
        delay=1,
        timeout=45,
        retries=5,
        technique='BEUSTQ',
        tamper='space2comment,between,randomcase,charencode',
        max_cycles=80,
        random_agent=True,
        tor_recommended=False,
        options={
            'safe_url_check': False,
            'skip_waf': False,
            'crawl_depth': 5,
            'forms': True,
            'dump_all': True,
            'exclude_sysdbs': True,
        }
    ),
    'speed': ScanProfile(
        name='Speed',
        description='Maximum speed scan. High threads, no delay, basic techniques only. '
                    'Best for quick vulnerability checks on many targets.',
        level=1,
        risk=1,
        threads=10,
        delay=0,
        timeout=10,
        retries=1,
        technique='BEU',
        tamper='',
        max_cycles=10,
        random_agent=True,
        tor_recommended=False,
        options={
            'safe_url_check': False,
            'skip_waf': True,
            'crawl_depth': 0,
        }
    ),
    'waf_buster': ScanProfile(
        name='WAF Buster',
        description='Specialized for WAF bypass. Progressive tamper escalation, '
                    'smart delay, encoding chains. Best when WAF is detected.',
        level=3,
        risk=2,
        threads=2,
        delay=4,
        timeout=40,
        retries=5,
        technique='BT',
        tamper='randomcomments,space2comment,between,chardoubleencode,charunicodeencode,base64encode',
        max_cycles=40,
        random_agent=True,
        tor_recommended=True,
        options={
            'safe_url_check': True,
            'skip_waf': False,
            'crawl_depth': 0,
            'hpp': True,
        }
    ),
}


def get_profile(name: str) -> Optional[ScanProfile]:
    return SCAN_PROFILES.get(name.lower())


def list_profiles() -> List[Dict[str, Any]]:
    return [
        {
            'id': pid,
            'name': p.name,
            'description': p.description,
            'level': p.level,
            'risk': p.risk,
            'threads': p.threads,
            'delay': p.delay,
            'max_cycles': p.max_cycles,
            'technique': p.technique,
            'tamper': p.tamper,
            'tor_recommended': p.tor_recommended,
        }
        for pid, p in SCAN_PROFILES.items()
    ]


def apply_profile(profile_name: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Apply a scan profile and return the merged options dict for the runner."""
    profile = get_profile(profile_name)
    if not profile:
        return {}

    opts: Dict[str, Any] = {
        'level': profile.level,
        'risk': profile.risk,
        'threads': profile.threads,
        'delay': profile.delay,
        'timeout': profile.timeout,
        'retries': profile.retries,
        'technique': profile.technique,
        'tamper': profile.tamper,
        'max_cycles': profile.max_cycles,
        'random_agent': profile.random_agent,
        'tor': profile.tor_recommended,
    }
    opts.update(profile.options)

    if overrides:
        opts.update(overrides)

    return opts
