"""Durable run journal for plans, decisions, and tool execution."""

from __future__ import annotations

import json
import time
from pathlib import Path


class RunJournal:
    def __init__(self, target: str, logs_dir: Path):
        logs_dir.mkdir(exist_ok=True)
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('.', '_').replace(':', '_')
        self.path = logs_dir / f'{timestamp}_{safe_target}.jsonl'
        self._fh = self.path.open('a')

    def write(self, event_type: str, payload: dict):
        record = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'event': event_type,
            'payload': payload,
        }
        self._fh.write(json.dumps(record, sort_keys=True) + '\n')
        self._fh.flush()

    def close(self):
        self._fh.close()
