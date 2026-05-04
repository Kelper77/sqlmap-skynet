"""
Notification System — Discord, Telegram, and generic Webhook alerts.
Sends alerts when vulnerabilities are found, scans complete, or WAFs are bypassed.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

import aiohttp

from core.debug_logger import logger


class NotifyEvent(Enum):
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    VULN_FOUND = "vuln_found"
    WAF_DETECTED = "waf_detected"
    WAF_BYPASSED = "waf_bypassed"
    DUMP_FOUND = "dump_found"
    ERROR = "error"


class NotificationManager:
    """Manage and dispatch notifications across multiple channels."""

    def __init__(self):
        self.channels: Dict[str, Dict[str, Any]] = {}
        self.enabled = True
        self.history: List[Dict[str, Any]] = []
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Auto-configure from environment variables."""
        discord_url = os.getenv('SKYNET_DISCORD_WEBHOOK')
        if discord_url:
            self.add_channel('discord', 'discord', {'webhook_url': discord_url})

        telegram_token = os.getenv('SKYNET_TELEGRAM_TOKEN')
        telegram_chat = os.getenv('SKYNET_TELEGRAM_CHAT_ID')
        if telegram_token and telegram_chat:
            self.add_channel('telegram', 'telegram', {
                'bot_token': telegram_token,
                'chat_id': telegram_chat,
            })

        webhook_url = os.getenv('SKYNET_WEBHOOK_URL')
        if webhook_url:
            self.add_channel('webhook', 'webhook', {'url': webhook_url})

    def add_channel(self, channel_id: str, channel_type: str,
                    config: Dict[str, Any]) -> None:
        self.channels[channel_id] = {
            'type': channel_type,
            'config': config,
            'enabled': True,
            'events': list(NotifyEvent),
        }
        logger.info("NOTIFY", f"Channel added: {channel_id} ({channel_type})")

    def remove_channel(self, channel_id: str) -> None:
        self.channels.pop(channel_id, None)

    def list_channels(self) -> List[Dict[str, Any]]:
        return [
            {
                'id': cid,
                'type': c['type'],
                'enabled': c['enabled'],
                'events': [e.value for e in c['events']],
            }
            for cid, c in self.channels.items()
        ]

    async def notify(self, event: NotifyEvent, data: Dict[str, Any]) -> None:
        """Send notification to all enabled channels subscribed to this event."""
        if not self.enabled or not self.channels:
            return

        self.history.append({
            'event': event.value,
            'data': data,
            'timestamp': datetime.now().isoformat(),
        })

        tasks = []
        for cid, channel in self.channels.items():
            if not channel['enabled']:
                continue
            if event not in channel['events']:
                continue
            tasks.append(self._dispatch(cid, channel, event, data))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _dispatch(self, channel_id: str, channel: Dict,
                        event: NotifyEvent, data: Dict) -> None:
        ctype = channel['type']
        try:
            if ctype == 'discord':
                await self._send_discord(channel['config'], event, data)
            elif ctype == 'telegram':
                await self._send_telegram(channel['config'], event, data)
            elif ctype == 'webhook':
                await self._send_webhook(channel['config'], event, data)
        except Exception as e:
            logger.error("NOTIFY", f"Failed to send to {channel_id}: {e}")

    def _build_message(self, event: NotifyEvent, data: Dict) -> str:
        """Build a human-readable notification message."""
        target = data.get('target', 'Unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if event == NotifyEvent.SCAN_START:
            return (f"🚀 **SCAN STARTED**\n"
                    f"Target: `{target}`\n"
                    f"Method: {data.get('method', 'GET')}\n"
                    f"Profile: {data.get('profile', 'balanced')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.SCAN_COMPLETE:
            return (f"✅ **SCAN COMPLETE**\n"
                    f"Target: `{target}`\n"
                    f"Injection Found: {'YES 🔴' if data.get('injection_found') else 'NO'}\n"
                    f"Databases: {data.get('databases', 0)}\n"
                    f"Tables: {data.get('tables', 0)}\n"
                    f"Cycles: {data.get('cycles', 0)}\n"
                    f"Duration: {data.get('duration', 'N/A')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.VULN_FOUND:
            return (f"🔴 **VULNERABILITY FOUND**\n"
                    f"Target: `{target}`\n"
                    f"Type: {data.get('vuln_type', 'SQL Injection')}\n"
                    f"Technique: {data.get('technique', 'Unknown')}\n"
                    f"DBMS: {data.get('dbms', 'Unknown')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.WAF_DETECTED:
            return (f"🛡️ **WAF DETECTED**\n"
                    f"Target: `{target}`\n"
                    f"WAF: {data.get('waf_type', 'Unknown')}\n"
                    f"Confidence: {data.get('confidence', 'N/A')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.WAF_BYPASSED:
            return (f"💥 **WAF BYPASSED**\n"
                    f"Target: `{target}`\n"
                    f"WAF: {data.get('waf_type', 'Unknown')}\n"
                    f"Bypass: {data.get('bypass_technique', 'Unknown')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.DUMP_FOUND:
            return (f"📦 **HIGH-VALUE DATA FOUND**\n"
                    f"Target: `{target}`\n"
                    f"Database: {data.get('database', 'Unknown')}\n"
                    f"Table: {data.get('table', 'Unknown')}\n"
                    f"Columns: {data.get('columns', 'Unknown')}\n"
                    f"Time: {timestamp}")

        if event == NotifyEvent.ERROR:
            return (f"⚠️ **SCAN ERROR**\n"
                    f"Target: `{target}`\n"
                    f"Error: {data.get('error', 'Unknown')}\n"
                    f"Time: {timestamp}")

        return f"📡 SKYNET Event: {event.value}\n{json.dumps(data, indent=2)}"

    async def _send_discord(self, config: Dict, event: NotifyEvent,
                            data: Dict) -> None:
        message = self._build_message(event, data)
        payload = {
            'content': message,
            'username': 'SKYNET Scanner',
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config['webhook_url'],
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status not in (200, 204):
                    logger.warning("NOTIFY", f"Discord returned {resp.status}")

    async def _send_telegram(self, config: Dict, event: NotifyEvent,
                             data: Dict) -> None:
        message = self._build_message(event, data)
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        payload = {
            'chat_id': config['chat_id'],
            'text': message,
            'parse_mode': 'Markdown',
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    logger.warning("NOTIFY", f"Telegram returned {resp.status}")

    async def _send_webhook(self, config: Dict, event: NotifyEvent,
                            data: Dict) -> None:
        payload = {
            'event': event.value,
            'data': data,
            'timestamp': datetime.now().isoformat(),
            'source': 'sqlmap-skynet',
        }
        headers = config.get('headers', {'Content-Type': 'application/json'})
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config['url'],
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status >= 400:
                    logger.warning("NOTIFY", f"Webhook returned {resp.status}")


notifications = NotificationManager()
