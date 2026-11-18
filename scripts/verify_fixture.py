#!/usr/bin/env python3
"""Verify the bundled synthetic fixture without Docker or extra dependencies."""
from pathlib import Path
import json

root = Path(__file__).resolve().parent.parent
fixture = root / 'data' / 'dataset_full.json'
assert fixture.is_file(), f'Missing {fixture}'
records = json.loads(fixture.read_text(encoding='utf-8'))['Records']
ids = [r['eventID'] for r in records]
gz_files = list((root / 'data' / 's3_layout').rglob('*.json.gz'))
required = {'eventID', 'eventTime', 'eventName', 'eventSource', 'userIdentity', 'sourceIPAddress'}
assert len(records) == 265, f'Expected 265 events, got {len(records)}'
assert len(ids) == len(set(ids)), 'Duplicate eventID in synthetic fixture'
assert len(gz_files) == 114, f'Expected 114 compressed files, got {len(gz_files)}'
assert all(required <= r.keys() for r in records), 'Missing core CloudTrail fields'
print(f'OK: {len(records)} synthetic events, {len(gz_files)} gzip files, unique event IDs')
