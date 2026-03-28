"""API client wrappers for OpenAI and Deepseek — extracted from app.py."""

import os
import logging
import requests
import openai


class _APIResponse:
    """Simple normalized response wrapper for both OpenAI and Deepseek responses."""

    def __init__(self, content: str):
        self._content = content

    @property
    def choices(self):
        return [self]

    @property
    def message(self):
        return self

    @property
    def content(self):
        return self._content


class APIClient:
    def __init__(self, api_type: str):
        self.api_type = api_type.lower()
        if self.api_type == "openai":
            self._openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        elif self.api_type == "deepseek":
            self.session = requests.Session()
            self.session.headers.update({
                "Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}",
                "Content-Type": "application/json"
            })
        else:
            raise ValueError("Unsupported API type. Please use 'openai' or 'deepseek'.")

    def create_completion(self, messages: list, **kwargs) -> _APIResponse:
        """Create completion with the chosen API provider, always returning an _APIResponse."""
        try:
            if self.api_type == "openai":
                response = self._openai_client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-3.5-turbo"),
                    messages=messages,
                    temperature=kwargs.get('temperature', 0.1),
                    max_tokens=kwargs.get('max_tokens', 3000)
                )
                content = response.choices[0].message.content
                return _APIResponse(content)

            elif self.api_type == "deepseek":
                payload = {
                    "model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
                    "messages": messages,
                    "temperature": kwargs.get('temperature', 0.1),
                    "max_tokens": kwargs.get('max_tokens', 3000),
                    "stream": False
                }
                response = self.session.post(
                    "https://api.deepseek.com/v1/chat/completions", json=payload
                )
                resp_data = response.json()
                if not resp_data.get('choices'):
                    raise ValueError("No response choices available")
                content = resp_data['choices'][0]['message'].get('content')
                if not content:
                    raise ValueError("No content in API response")
                return _APIResponse(content)

        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            raise ValueError(f"API request failed: {str(e)}")
        except Exception as e:
            logging.error(f"API error: {str(e)}")
            raise ValueError(f"API error: {str(e)}")


class APIOptimizer:
    def __init__(self):
        import hashlib
        import json
        from pathlib import Path

        self._hashlib = hashlib
        self._json = json

        _cache_duration = int(os.getenv("CACHE_DURATION", "86400"))
        self._cache_duration = _cache_duration
        _cache_dir = Path("cache")
        _cache_dir.mkdir(exist_ok=True)
        self.cache_file = _cache_dir / "analysis_cache.json"
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.cache = {}

    def get_code_hash(self, code: str) -> str:
        return self._hashlib.sha256(code.encode()).hexdigest()

    def _make_cache_key(self, code: str, query) -> str:
        """Build a deterministic cache key from code content and query."""
        code_hash = self.get_code_hash(code)
        query_hash = self._hashlib.sha256(str(query).encode()).hexdigest() if query else "full_scan"
        return f"{code_hash}_{query_hash}"

    def get_cached_analysis(self, code: str, query: str = None) -> dict:
        """Retrieve cached analysis if available and fresh."""
        from datetime import datetime
        cache_key = self._make_cache_key(code, query)
        if cache_key in self.cache:
            cached_time = datetime.fromisoformat(self.cache[cache_key]['timestamp'])
            if (datetime.now() - cached_time).total_seconds() < self._cache_duration:
                return self.cache[cache_key]['results']
        return None

    def cache_analysis(self, code: str, query: str, results: dict):
        """Store analysis results in cache for later use."""
        from datetime import datetime
        cache_key = self._make_cache_key(code, query)
        self.cache[cache_key] = {
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.cache_file, 'w') as f:
                self._json.dump(self.cache, f)
            os.chmod(self.cache_file, 0o600)
        except IOError as e:
            logging.error(f"Cache write error: {str(e)}")
