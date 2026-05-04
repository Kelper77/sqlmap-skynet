"""
Multi-AI Consensus Engine — Query multiple AI providers simultaneously
and use voting/consensus for higher accuracy recommendations.
"""
import asyncio
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import Counter

import aiohttp

from core.debug_logger import logger


class ConsensusResult:
    """Result from multi-AI consensus voting."""

    def __init__(self, responses: List[Dict[str, Any]]):
        self.responses = responses
        self.consensus_text = ''
        self.confidence = 0.0
        self.provider_count = len(responses)
        self.agreement_score = 0.0
        self.recommended_action = ''
        self.recommended_tamper = ''
        self.recommended_technique = ''
        self._analyze()

    def _analyze(self) -> None:
        """Analyze responses and build consensus."""
        if not self.responses:
            return

        valid = [r for r in self.responses if r.get('response')]
        if not valid:
            return

        # Extract key recommendations from each response
        tampers: List[str] = []
        techniques: List[str] = []
        actions: List[str] = []

        for resp in valid:
            text = resp['response'].lower()
            # Extract tamper scripts mentioned
            found_tampers = re.findall(
                r'(?:tamper|--tamper)[=:\s]+([a-z0-9_,]+)', text
            )
            for t in found_tampers:
                tampers.extend(t.split(','))

            # Extract technique suggestions
            if 'time-based' in text or 'time based' in text:
                techniques.append('T')
            if 'boolean-based' in text or 'boolean based' in text:
                techniques.append('B')
            if 'union' in text:
                techniques.append('U')
            if 'error-based' in text or 'error based' in text:
                techniques.append('E')
            if 'stacked' in text:
                techniques.append('S')

            # Extract action recommendations
            if any(w in text for w in ['increase delay', 'slow down', 'add delay']):
                actions.append('increase_delay')
            if any(w in text for w in ['increase level', 'higher level']):
                actions.append('increase_level')
            if any(w in text for w in ['increase risk', 'higher risk']):
                actions.append('increase_risk')
            if any(w in text for w in ['use tor', 'enable tor']):
                actions.append('enable_tor')

        # Vote on tampers
        tamper_counts = Counter(t.strip() for t in tampers if t.strip())
        if tamper_counts:
            top_tampers = [t for t, _ in tamper_counts.most_common(5)]
            self.recommended_tamper = ','.join(top_tampers)

        # Vote on techniques
        tech_counts = Counter(techniques)
        if tech_counts:
            self.recommended_technique = ''.join(
                t for t, _ in tech_counts.most_common(6)
            )

        # Vote on actions
        action_counts = Counter(actions)
        if action_counts:
            self.recommended_action = action_counts.most_common(1)[0][0]

        # Calculate agreement score
        if len(valid) >= 2:
            agreements = 0
            total_comparisons = 0
            for i in range(len(valid)):
                for j in range(i + 1, len(valid)):
                    total_comparisons += 1
                    t1 = set(re.findall(r'\b\w+\b', valid[i]['response'].lower()))
                    t2 = set(re.findall(r'\b\w+\b', valid[j]['response'].lower()))
                    overlap = len(t1 & t2) / max(len(t1 | t2), 1)
                    agreements += overlap
            self.agreement_score = agreements / max(total_comparisons, 1)

        self.confidence = min(1.0, (len(valid) / max(self.provider_count, 1)) * 0.5
                              + self.agreement_score * 0.5)

        # Use the longest response as the consensus text
        best = max(valid, key=lambda r: len(r.get('response', '')))
        self.consensus_text = best['response']

    def to_dict(self) -> Dict[str, Any]:
        return {
            'consensus_text': self.consensus_text[:2000],
            'confidence': round(self.confidence, 2),
            'agreement_score': round(self.agreement_score, 2),
            'provider_count': self.provider_count,
            'successful_providers': len([r for r in self.responses if r.get('response')]),
            'recommended_tamper': self.recommended_tamper,
            'recommended_technique': self.recommended_technique,
            'recommended_action': self.recommended_action,
            'providers_used': [r.get('provider', 'unknown') for r in self.responses],
        }


class MultiAIConsensus:
    """Query multiple AI providers in parallel and build consensus."""

    PROVIDER_CONFIGS = {
        'ollama': {
            'local': True,
            'url': 'http://localhost:11434/api/generate',
            'timeout': 60,
        },
        'openai': {
            'local': False,
            'url': 'https://api.openai.com/v1/chat/completions',
            'model': 'gpt-4o',
            'env_key': 'OPENAI_API_KEY',
            'timeout': 30,
        },
        'groq': {
            'local': False,
            'url': 'https://api.groq.com/openai/v1/chat/completions',
            'model': 'llama-3.3-70b-versatile',
            'env_key': 'GROQ_API_KEY',
            'timeout': 20,
        },
        'deepseek': {
            'local': False,
            'url': 'https://api.deepseek.com/v1/chat/completions',
            'model': 'deepseek-coder',
            'env_key': 'DEEPSEEK_API_KEY',
            'timeout': 30,
        },
        'claude': {
            'local': False,
            'url': 'https://api.anthropic.com/v1/messages',
            'model': 'claude-3-5-sonnet-20241022',
            'env_key': 'ANTHROPIC_API_KEY',
            'timeout': 30,
        },
        'kimi': {
            'local': False,
            'url': 'https://api.moonshot.cn/v1/chat/completions',
            'model': 'kimi-latest',
            'env_key': 'KIMI_API_KEY',
            'timeout': 30,
        },
    }

    def __init__(self):
        import os
        self.available_providers: List[str] = []
        self._detect_providers(os.environ)
        self.consensus_history: List[Dict[str, Any]] = []

    def _detect_providers(self, env: Dict) -> None:
        """Detect which providers are available."""
        import os
        for name, cfg in self.PROVIDER_CONFIGS.items():
            if cfg.get('local'):
                try:
                    import subprocess
                    result = subprocess.run(
                        ['ollama', 'list'], capture_output=True, timeout=5
                    )
                    if result.returncode == 0:
                        self.available_providers.append(name)
                except Exception:
                    pass
            else:
                key = os.getenv(cfg.get('env_key', ''))
                if key:
                    self.available_providers.append(name)

        logger.info("MULTI-AI", f"Available providers: {self.available_providers}")

    async def consensus_query(self, prompt: str,
                              min_providers: int = 2,
                              timeout: int = 60) -> ConsensusResult:
        """Query all available providers in parallel and build consensus."""
        providers_to_query = self.available_providers[:6]

        if len(providers_to_query) < min_providers:
            logger.warning("MULTI-AI",
                           f"Only {len(providers_to_query)} providers available "
                           f"(need {min_providers})")

        tasks = [
            self._query_provider(name, prompt, timeout)
            for name in providers_to_query
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses = []
        for i, result in enumerate(results):
            provider = providers_to_query[i]
            if isinstance(result, Exception):
                responses.append({
                    'provider': provider,
                    'response': None,
                    'error': str(result),
                    'latency_ms': 0,
                })
            else:
                responses.append(result)

        consensus = ConsensusResult(responses)

        self.consensus_history.append({
            'timestamp': datetime.now().isoformat(),
            'prompt_preview': prompt[:100],
            'result': consensus.to_dict(),
        })

        logger.info("MULTI-AI",
                     f"Consensus built: {consensus.confidence:.0%} confidence, "
                     f"{len([r for r in responses if r.get('response')])}/"
                     f"{len(responses)} providers responded")

        return consensus

    async def _query_provider(self, name: str, prompt: str,
                              timeout: int) -> Dict[str, Any]:
        """Query a single provider."""
        import os
        import time
        cfg = self.PROVIDER_CONFIGS[name]
        start = time.time()

        try:
            if cfg.get('local'):
                response = await self._query_ollama(prompt, timeout)
            elif name == 'claude':
                response = await self._query_claude(cfg, prompt, timeout)
            else:
                response = await self._query_openai_compat(cfg, prompt, timeout)

            latency = int((time.time() - start) * 1000)
            return {
                'provider': name,
                'response': response,
                'error': None,
                'latency_ms': latency,
            }
        except Exception as e:
            return {
                'provider': name,
                'response': None,
                'error': str(e),
                'latency_ms': int((time.time() - start) * 1000),
            }

    async def _query_ollama(self, prompt: str, timeout: int) -> Optional[str]:
        import config as cfg_module
        model = cfg_module.OLLAMA_MODELS.get('default', 'llama3.2:latest')
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'http://localhost:11434/api/generate',
                json={'model': model, 'prompt': prompt, 'stream': False,
                      'options': {'temperature': 0.3}},
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('response', '')
        return None

    async def _query_openai_compat(self, cfg: Dict, prompt: str,
                                   timeout: int) -> Optional[str]:
        import os
        key = os.getenv(cfg['env_key'])
        if not key:
            return None
        headers = {
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system',
                 'content': 'You are a SQL injection expert. Be concise and actionable.'},
                {'role': 'user', 'content': prompt},
            ],
            'max_tokens': 2000,
            'temperature': 0.3,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg['url'], headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['choices'][0]['message']['content']
        return None

    async def _query_claude(self, cfg: Dict, prompt: str,
                            timeout: int) -> Optional[str]:
        import os
        key = os.getenv(cfg['env_key'])
        if not key:
            return None
        headers = {
            'x-api-key': key,
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01',
        }
        payload = {
            'model': cfg['model'],
            'max_tokens': 2000,
            'messages': [{'role': 'user', 'content': prompt}],
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg['url'], headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['content'][0]['text']
        return None


multi_ai = MultiAIConsensus()
