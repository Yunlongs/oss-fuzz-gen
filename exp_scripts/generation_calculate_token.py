#!/usr/bin/env python3
"""
Parse log files and calculate token usage statistics.
"""

import re
import sys
from typing import Dict, List
from pathlib import Path
from datetime import datetime
import os


OUTPUT_DIR = "/home/lyuyunlong/work/oss-fuzz-gen/output"

def parse_token_usage(log_file_path: str) -> List[Dict[str, int]]:
    """
    Parse token usage from log file.
    
    Args:
        log_file_path: Path to the log file
        
    Returns:
        List of dictionaries containing token usage information
    """
    token_pattern = re.compile(
        r'Token usage - prompt: (\d+), completion: (\d+), total: (\d+), cached: (\d+)'
    )
    time_pattern = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})'
    )
    
    token_records = []
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            match = token_pattern.search(line)
            if match:
                record = {
                    'prompt': int(match.group(1)),
                    'completion': int(match.group(2)),
                    'total': int(match.group(3)),
                    'cached': int(match.group(4)),
                    'time': None
                }
                time_match = time_pattern.search(line)
                if time_match:
                    try:
                        record['time'] = datetime.strptime(time_match.group(1), '%Y-%m-%d %H:%M:%S,%f')
                    except ValueError:
                        pass
                token_records.append(record)
    
    return token_records


def calculate_statistics(token_records: List[Dict]) -> Dict[str, float]:
    """
    Calculate token usage statistics.
    
    Args:
        token_records: List of token usage records
        
    Returns:
        Dictionary with aggregated statistics
    """
    if not token_records:
        return {
            'total_prompt': 0,
            'total_completion': 0,
            'total_tokens': 0,
            'total_cached': 0,
            'num_requests': 0,
            'avg_time_between_requests': 0.0,
            'total_time': 0.0
        }
    
    stats = {
        'total_prompt': sum(r['prompt'] for r in token_records),
        'total_completion': sum(r['completion'] for r in token_records),
        'total_tokens': sum(r['total'] for r in token_records),
        'total_cached': sum(r['cached'] for r in token_records),
        'num_requests': len(token_records)
    }
    
    # Calculate intervals
    time_intervals = []
    # Sort records by time if time information exists
    time_records = [r['time'] for r in token_records if r.get('time')]
    if len(time_records) >= 2:
        time_records.sort()
        for i in range(1, len(time_records)):
            delta = (time_records[i] - time_records[i-1]).total_seconds()
            time_intervals.append(delta)
    
    if time_intervals:
        stats['avg_time_between_requests'] = sum(time_intervals) / len(time_intervals)
        stats['total_time'] = sum(time_intervals)
    else:
        stats['avg_time_between_requests'] = 0.0
        stats['total_time'] = 0.0
    
    # Calculate unique tokens (total - cached)
    stats['total_unique'] = stats['total_tokens'] - stats['total_cached']
    
    return stats


# Pricing per 1M tokens (USD)
PRICE_CACHE_HIT_PER_1M = 0.028    # cached input tokens
PRICE_CACHE_MISS_PER_1M = 0.28    # non-cached input tokens
PRICE_OUTPUT_PER_1M = 0.42        # output (completion) tokens


def calculate_cost(stats: Dict[str, int]) -> Dict[str, float]:
    """
    Calculate estimated cost based on token usage.
    
    Args:
        stats: Token usage statistics
        
    Returns:
        Dictionary with cost breakdown
    """
    cached_input = stats['total_cached']
    uncached_input = stats['total_prompt'] - stats['total_cached']
    output = stats['total_completion']

    cost_cache_hit = cached_input / 1_000_000 * PRICE_CACHE_HIT_PER_1M
    cost_cache_miss = uncached_input / 1_000_000 * PRICE_CACHE_MISS_PER_1M
    cost_output = output / 1_000_000 * PRICE_OUTPUT_PER_1M

    return {
        'cost_cache_hit': cost_cache_hit,
        'cost_cache_miss': cost_cache_miss,
        'cost_output': cost_output,
        'cost_total': cost_cache_hit + cost_cache_miss + cost_output
    }


def print_statistics(stats: Dict[str, float]):
    """Print token usage statistics in a readable format."""
    print("\n" + "="*60)
    print("Token Usage Statistics")
    print("="*60)
    print(f"Number of requests:     {stats['num_requests']:,}")
    print("-"*60)
    print(f"Total prompt tokens:    {stats['total_prompt']:,}")
    print(f"Total completion tokens:{stats['total_completion']:,}")
    print(f"Total tokens:           {stats['total_tokens']:,}")
    print(f"Total cached tokens:    {stats['total_cached']:,}")
    print(f"Total unique tokens:    {stats['total_unique']:,}")
    print("-"*60)
    if 'avg_time_between_requests' in stats and stats['avg_time_between_requests'] > 0:
        print(f"Avg time b/w requests:  {stats['avg_time_between_requests']:.2f} seconds")
        print(f"Total est. time:        {stats['total_time']:.2f} seconds")
        print("-"*60)

    if stats['num_requests'] > 0:
        print(f"Average prompt/request: {stats['total_prompt'] / stats['num_requests']:,.2f}")
        print(f"Average completion/req: {stats['total_completion'] / stats['num_requests']:,.2f}")
        print(f"Average total/request:  {stats['total_tokens'] / stats['num_requests']:,.2f}")
        print(f"Cache hit rate:         {stats['total_cached'] / stats['total_tokens'] * 100:.2f}%")

    costs = calculate_cost(stats)
    uncached_input = stats['total_prompt'] - stats['total_cached']
    print("="*60)
    print("Cost Estimate")
    print(f"  Pricing: cache hit ${PRICE_CACHE_HIT_PER_1M}/1M | "
          f"cache miss ${PRICE_CACHE_MISS_PER_1M}/1M | "
          f"output ${PRICE_OUTPUT_PER_1M}/1M")
    print("-"*60)
    print(f"  Cached input  ({stats['total_cached']:>15,} tokens): ${costs['cost_cache_hit']:.4f}")
    print(f"  Uncached input({uncached_input:>15,} tokens): ${costs['cost_cache_miss']:.4f}")
    print(f"  Output        ({stats['total_completion']:>15,} tokens): ${costs['cost_output']:.4f}")
    print("-"*60)
    print(f"  Total estimated cost:                    ${costs['cost_total']:.4f}")
    print("="*60 + "\n")


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python calculate_token_cost.py <project_name>")
        print("\nExample:")
        print("  python calculate_token_cost.py myproject")
        sys.exit(1)
    
    project_name = sys.argv[1]
    project_output_dir = os.path.join(OUTPUT_DIR, project_name)
    log_file_path = os.path.join(project_output_dir, "run_all_experiments.log")

    if not Path(log_file_path).exists():
        print(f"Error: Log file '{log_file_path}' not found.")
        sys.exit(1)
    
    print(f"Parsing log file: {log_file_path}")
    
    # Parse token usage records
    token_records = parse_token_usage(log_file_path)
    
    if not token_records:
        print("\nNo token usage records found in the log file.")
        print("Expected format: Token usage - prompt: X, completion: Y, total: Z, cached: W")
        sys.exit(0)
    
    # Calculate statistics
    stats = calculate_statistics(token_records)
    
    # Print results
    print_statistics(stats)


if __name__ == '__main__':
    main()
