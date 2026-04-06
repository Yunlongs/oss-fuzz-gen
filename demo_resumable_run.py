#!/usr/bin/env python3
"""
Demonstration script for resumable run feature.

This script demonstrates the resumable run workflow:
1. Show current status in file project
2. Simulate filtering completed benchmarks
3. Display what would be run in resume mode
"""

import os
import sys
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checkpoint_manager import CheckpointManager
from experiment.benchmark import Benchmark


def demo_resume_workflow():
    """Demonstrate the resume workflow."""
    
    file_output_dir = '/home/lyuyunlong/work/oss-fuzz-gen/output/file'
    benchmark_dir = '/home/lyuyunlong/work/oss-fuzz-gen/benchmark-sets/file'
    
    if not os.path.exists(file_output_dir):
        print(f"Error: {file_output_dir} not found")
        return False
    
    print("\n" + "="*70)
    print("RESUMABLE RUN FEATURE DEMONSTRATION")
    print("="*70)
    
    # Step 1: Load all benchmarks
    print("\n[Step 1] Loading all benchmarks from file project...")
    all_benchmarks = []
    
    for yaml_file in os.listdir(benchmark_dir):
        if not (yaml_file.endswith('.yaml') or yaml_file.endswith('.yml')):
            continue
        yaml_path = os.path.join(benchmark_dir, yaml_file)
        try:
            benchmarks = Benchmark.from_yaml(yaml_path)
            all_benchmarks.extend(benchmarks)
        except Exception as e:
            # Skip files that can't be loaded
            pass
    
    print(f"✓ Loaded {len(all_benchmarks)} benchmarks")
    
    # Step 2: Initialize checkpoint manager
    print("\n[Step 2] Initializing checkpoint manager...")
    cm = CheckpointManager(file_output_dir)
    
    # Step 3: Scan completed experiments
    print("\n[Step 3] Scanning for completed experiments...")
    resume_info = cm.get_resume_info()
    
    print(f"✓ Found {resume_info['completed_count']} completed experiments")
    print(f"✓ Found {resume_info['pending_count']} pending/pending experiments")
    
    # Step 4: Show what would be in fresh vs resume mode
    print("\n[Step 4] Comparison: Fresh mode vs Resume mode")
    print("-" * 70)
    
    completed_ids = resume_info['completed']
    
    # All benchmarks that would run in fresh mode
    fresh_targets = [b for b in all_benchmarks]
    
    # Benchmarks that would run in resume mode
    resume_targets = [b for b in all_benchmarks 
                      if b.id not in completed_ids]
    
    print(f"Fresh mode:  {len(fresh_targets):2d} experiments (clean start)")
    print(f"Resume mode: {len(resume_targets):2d} experiments (skip {len(completed_ids)} completed)")
    
    # Show breakdown
    print("\n[Step 5] Experiment breakdown:")
    print("-" * 70)
    
    # Count by project inside
    project_stats = {}
    for b in all_benchmarks:
        project = b.project
        if project not in project_stats:
            project_stats[project] = {'total': 0, 'completed': 0}
        project_stats[project]['total'] += 1
        if b.id in completed_ids:
            project_stats[project]['completed'] += 1
    
    for project in sorted(project_stats.keys()):
        stats = project_stats[project]
        total = stats['total']
        completed = stats['completed']
        remaining = total - completed
        
        pct = (completed / total * 100) if total > 0 else 0
        bar = '█' * int(pct / 5) + '░' * (20 - int(pct / 5))
        
        print(f"  {project:20s} {completed:2d}/{total:2d} done {bar:20s} {pct:5.1f}%")
    
    # Step 6: Show detailed status
    print("\n[Step 6] Detailed status of first 10 benchmarks:")
    print("-" * 70)
    
    for i, bid in enumerate(sorted(completed_ids)[:10]):
        status = "completed"
        cm.scan_completed_experiments()
        timestamp = cm.registry.get(bid, {}).get('timestamp', 'N/A')
        status_indicator = "✓"
        print(f"  {status_indicator} {bid:40s} {timestamp}")
    
    if len(completed_ids) > 10:
        print(f"  ... and {len(completed_ids) - 10} more completed")
    
    # Step 7: Estimate time savings
    print("\n[Step 7] Estimated benefit of resume mode:")
    print("-" * 70)
    
    # Rough estimate: each experiment takes ~5-10 minutes
    # (very rough, depends on LLM calls, compilation, etc.)
    avg_time_per_exp = 8  # minutes (conservative estimate)
    
    fresh_time = len(fresh_targets) * avg_time_per_exp
    resume_time = len(resume_targets) * avg_time_per_exp
    saved_time = fresh_time - resume_time
    saved_hours = saved_time / 60
    
    print(f"  Fresh mode estimated time:  {fresh_time:4d} minutes (~{fresh_time/60:4.1f} hours)")
    print(f"  Resume mode estimated time: {resume_time:4d} minutes (~{resume_time/60:4.1f} hours)")
    print(f"  Time saved by resume mode:  {saved_time:4d} minutes (~{saved_hours:4.1f} hours)")
    print(f"  Efficiency gain:            {100 * saved_time / fresh_time:5.1f}%")
    
    # Step 8: Show commands
    print("\n[Step 8] How to use resume mode:")
    print("-" * 70)
    print("""
# View current status (no execution)
python run_all_experiments.py \\
  -b benchmark-sets/file \\
  -w output/file \\
  -l gpt-4o-mini \\
  --resume-mode resume-only

# Resume execution from last completed point
python run_all_experiments.py \\
  -b benchmark-sets/file \\
  -w output/file \\
  -l gpt-4o-mini \\
  --resume-mode resume
""")
    
    print("\n" + "="*70)
    print("✅ DEMONSTRATION COMPLETE")
    print("="*70 + "\n")
    
    return True


if __name__ == '__main__':
    try:
        success = demo_resume_workflow()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
