"""
Scan History & Comparison Engine — Track all scans, diff sessions,
and provide trend analysis across targets.
"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from config import MEMORY_DIR
from core.debug_logger import logger


HISTORY_DIR = MEMORY_DIR / "history"
HISTORY_DIR.mkdir(exist_ok=True, parents=True)


class ScanHistoryManager:
    """Persistent scan history with comparison and trend analysis."""

    def __init__(self):
        self.history_file = HISTORY_DIR / "scan_history.json"
        self.scans: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        """Load scan history from disk."""
        if self.history_file.exists():
            try:
                data = json.loads(self.history_file.read_text(encoding='utf-8'))
                self.scans = data if isinstance(data, list) else []
                logger.info("HISTORY", f"Loaded {len(self.scans)} historical scans")
            except Exception as e:
                logger.error("HISTORY", f"Failed to load history: {e}")
                self.scans = []

    def _save(self) -> None:
        """Persist scan history to disk."""
        try:
            self.history_file.write_text(
                json.dumps(self.scans, indent=2, default=str),
                encoding='utf-8'
            )
        except Exception as e:
            logger.error("HISTORY", f"Failed to save history: {e}")

    def record_scan(self, session_id: str, target: str, results: Dict[str, Any],
                    profile: str = 'balanced', duration: str = 'N/A',
                    recon_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Record a completed scan in history."""
        entry = {
            'id': session_id,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'profile': profile,
            'duration': duration,
            'injection_found': results.get('injection_found', False),
            'databases': results.get('databases', []),
            'database_count': len(results.get('databases', [])),
            'table_count': sum(
                len(t) for t in results.get('tables', {}).values()
            ),
            'column_count': sum(
                len(c) for c in results.get('columns', {}).values()
            ),
            'techniques': results.get('techniques', []),
            'waf_detected': results.get('waf_detected'),
            'bypass_used': results.get('bypass_used'),
            'dbms_detected': results.get('dbms_detected'),
            'cycles': results.get('cycles', 0),
            'method': results.get('method', 'GET'),
            'ai_recommendations': len(results.get('ai_recommendations', [])),
            'web_searches': results.get('web_searches', 0),
            'recon': recon_data,
            'status': results.get('status', 'COMPLETED'),
        }

        self.scans.append(entry)
        self._save()
        logger.info("HISTORY", f"Scan recorded: {session_id} for {target}")
        return entry

    def get_history(self, limit: int = 50, target_filter: str = '',
                    status_filter: str = '') -> List[Dict[str, Any]]:
        """Retrieve scan history with optional filters."""
        filtered = self.scans

        if target_filter:
            filtered = [
                s for s in filtered
                if target_filter.lower() in s.get('target', '').lower()
            ]

        if status_filter:
            filtered = [
                s for s in filtered
                if s.get('status', '').lower() == status_filter.lower()
            ]

        return filtered[-limit:]

    def get_scan(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific scan by session ID."""
        for scan in self.scans:
            if scan.get('id') == session_id:
                return scan
        return None

    def compare_scans(self, scan_id_1: str,
                      scan_id_2: str) -> Dict[str, Any]:
        """Compare two scan sessions and return a diff."""
        scan1 = self.get_scan(scan_id_1)
        scan2 = self.get_scan(scan_id_2)

        if not scan1 or not scan2:
            return {'error': 'One or both scan IDs not found'}

        diff: Dict[str, Any] = {
            'scan_1': {'id': scan_id_1, 'target': scan1['target'],
                       'timestamp': scan1['timestamp']},
            'scan_2': {'id': scan_id_2, 'target': scan2['target'],
                       'timestamp': scan2['timestamp']},
            'changes': {},
        }

        # Compare key fields
        compare_fields = [
            'injection_found', 'database_count', 'table_count',
            'column_count', 'waf_detected', 'dbms_detected',
            'cycles', 'status', 'profile',
        ]
        for field in compare_fields:
            v1 = scan1.get(field)
            v2 = scan2.get(field)
            if v1 != v2:
                diff['changes'][field] = {'before': v1, 'after': v2}

        # Compare databases
        dbs1 = set(scan1.get('databases', []))
        dbs2 = set(scan2.get('databases', []))
        new_dbs = dbs2 - dbs1
        removed_dbs = dbs1 - dbs2
        if new_dbs or removed_dbs:
            diff['changes']['databases'] = {
                'new': list(new_dbs),
                'removed': list(removed_dbs),
            }

        # Compare techniques
        tech1 = set(scan1.get('techniques', []))
        tech2 = set(scan2.get('techniques', []))
        if tech1 != tech2:
            diff['changes']['techniques'] = {
                'new': list(tech2 - tech1),
                'removed': list(tech1 - tech2),
            }

        diff['has_changes'] = len(diff['changes']) > 0
        return diff

    def get_target_trends(self, target: str,
                          limit: int = 20) -> Dict[str, Any]:
        """Get trend analysis for a specific target over multiple scans."""
        target_scans = [
            s for s in self.scans
            if target.lower() in s.get('target', '').lower()
        ][-limit:]

        if not target_scans:
            return {'target': target, 'scan_count': 0, 'trends': {}}

        return {
            'target': target,
            'scan_count': len(target_scans),
            'first_scan': target_scans[0]['timestamp'],
            'last_scan': target_scans[-1]['timestamp'],
            'trends': {
                'injection_rate': sum(
                    1 for s in target_scans if s.get('injection_found')
                ) / len(target_scans),
                'avg_cycles': sum(
                    s.get('cycles', 0) for s in target_scans
                ) / len(target_scans),
                'avg_databases': sum(
                    s.get('database_count', 0) for s in target_scans
                ) / len(target_scans),
                'waf_changes': list(set(
                    s.get('waf_detected', 'None') for s in target_scans
                )),
                'profiles_used': list(set(
                    s.get('profile', 'balanced') for s in target_scans
                )),
                'techniques_seen': list(set(
                    t for s in target_scans
                    for t in s.get('techniques', [])
                )),
            },
            'scans': [
                {
                    'id': s['id'],
                    'timestamp': s['timestamp'],
                    'injection_found': s.get('injection_found', False),
                    'databases': s.get('database_count', 0),
                    'cycles': s.get('cycles', 0),
                    'status': s.get('status', ''),
                }
                for s in target_scans
            ],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get overall scan statistics."""
        if not self.scans:
            return {
                'total_scans': 0,
                'unique_targets': 0,
                'total_vulns_found': 0,
            }

        targets = set(s.get('target', '') for s in self.scans)
        vulns = sum(1 for s in self.scans if s.get('injection_found'))

        return {
            'total_scans': len(self.scans),
            'unique_targets': len(targets),
            'total_vulns_found': vulns,
            'success_rate': vulns / len(self.scans) if self.scans else 0,
            'total_databases_found': sum(
                s.get('database_count', 0) for s in self.scans
            ),
            'total_tables_found': sum(
                s.get('table_count', 0) for s in self.scans
            ),
            'most_used_profile': max(
                set(s.get('profile', 'balanced') for s in self.scans),
                key=lambda p: sum(
                    1 for s in self.scans if s.get('profile') == p
                ),
            ) if self.scans else 'balanced',
            'waf_encounter_rate': sum(
                1 for s in self.scans if s.get('waf_detected')
            ) / len(self.scans) if self.scans else 0,
        }


scan_history = ScanHistoryManager()
