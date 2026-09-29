#!/usr/bin/env python3
"""Summarize independent trial medians; does not pool latency percentiles."""
import argparse
import collections
import json
import statistics

parser = argparse.ArgumentParser()
parser.add_argument('results')
args = parser.parse_args()
groups = collections.defaultdict(list)
seen = set()
with open(args.results) as source:
    for line in source:
        row = json.loads(line)
        assert row['verified_after_reopen']
        identity = tuple(row[k] for k in ('mode', 'workload', 'concurrency', 'batch', 'engine', 'keys', 'repeat'))
        assert identity not in seen, f'Duplicate trial: {identity}; use a fresh output file'
        seen.add(identity)
        groups[tuple(row[k] for k in ('mode', 'workload', 'concurrency', 'batch', 'engine'))].append(row)
print('| Mode | Workload | Writers | Batch | Engine | Trials | Events/s median (min–max) | p50 ms | p99 ms | Retries/commit |')
print('|---|---|---:|---:|---|---:|---:|---:|---:|---:|')
for (mode, workload, concurrency, batch, engine), rows in sorted(groups.items()):
    rates = [r['events_per_sec'] for r in rows]
    p50 = statistics.median(r['p50_us'] for r in rows) / 1000
    p99 = statistics.median(r['p99_us'] for r in rows) / 1000
    retries = statistics.median(r['retries'] / r['transactions'] for r in rows)
    print(f'| {mode} | {workload} | {concurrency} | {batch} | {engine} | {len(rows)} | '
          f'{statistics.median(rates):,.0f} ({min(rates):,.0f}–{max(rates):,.0f}) | '
          f'{p50:.3f} | {p99:.3f} | {retries:.2f} |')
