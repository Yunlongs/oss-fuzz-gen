#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Checkpoint manager for resumable experiment runs."""

import json
import os
import re
from datetime import datetime
from typing import Dict, Optional, List
from logger_config import logger


class CheckpointManager:
  """Manages checkpoints for resumable experiment runs.
  
  This class handles:
  1. Scanning completed experiments from output directories
  2. Maintaining a global checkpoint registry
  3. Saving/loading checkpoint states
  4. Providing status information
  """

  CHECKPOINT_REGISTRY_FILE = '.checkpoint_registry.json'
  BENCHMARK_OUTPUT_PATTERN = re.compile(r'^output-([^-]+)-(.*)$')

  def __init__(self, work_dir: str):
    """Initialize checkpoint manager.
    
    Args:
      work_dir: Directory where outputs are stored
    """
    self.work_dir = work_dir
    self.registry_path = os.path.join(work_dir, self.CHECKPOINT_REGISTRY_FILE)
    self.registry = self._load_registry()

  def _load_registry(self) -> Dict:
    """Load checkpoint registry from file or create new one."""
    if os.path.exists(self.registry_path):
      try:
        with open(self.registry_path, 'r') as f:
          return json.load(f)
      except Exception as e:
        logger.warning(f'Failed to load checkpoint registry: {e}. Creating new one.')
        return {}
    return {}

  def _save_registry(self) -> None:
    """Save checkpoint registry to file."""
    os.makedirs(self.work_dir, exist_ok=True)
    with open(self.registry_path, 'w') as f:
      json.dump(self.registry, f, indent=2)

  def scan_completed_experiments(self) -> Dict[str, Dict]:
    """Scan work directory to find completed experiments.
    
    Returns:
      Dict mapping benchmark_id to their completion status and info
    """
    completed = {}
    fresh_registry: Dict[str, Dict] = {}
    
    if not os.path.exists(self.work_dir):
      logger.info(f'Work directory {self.work_dir} does not exist yet.')
      return completed

    for entry in os.listdir(self.work_dir):
      entry_path = os.path.join(self.work_dir, entry)
      
      # Skip if not a directory or is the registry file
      if not os.path.isdir(entry_path) or entry == self.CHECKPOINT_REGISTRY_FILE:
        continue

      # Check if this looks like an output directory
      if not entry.startswith('output-'):
        continue

      # Extract benchmark ID from directory name
      benchmark_id = self._extract_benchmark_id(entry)
      if not benchmark_id:
        continue

      # Check if experiment is completed
      result_info = self._check_experiment_status(entry_path)
      if result_info:
        fresh_registry[benchmark_id] = result_info
        if result_info.get('status') == 'completed':
          completed[benchmark_id] = result_info

    # Replace the registry with the current filesystem snapshot so stale
    # entries from earlier scans do not keep outdated completed states.
    self.registry = fresh_registry
    
    self._save_registry()
    return completed

  def _extract_benchmark_id(self, output_dir: str) -> Optional[str]:
    """Extract benchmark ID from output directory name.
    
    Args:
      output_dir: Directory name like 'output-file-magic_open'
      
    Returns:
      Benchmark ID like 'file-magic_open' or None if invalid
    """
    match = self.BENCHMARK_OUTPUT_PATTERN.match(output_dir)
    if match:
      project = match.group(1)
      function = match.group(2)
      return f'{project}-{function}'
    return None

  def _check_experiment_status(self, output_dir_path: str) -> Optional[Dict]:
    """Check if an experiment in the output directory is completed.
    
    Args:
      output_dir_path: Full path to the output directory
      
    Returns:
      Status dict if completed, None otherwise
    """
    has_fuzz_targets = self._has_artifacts(os.path.join(output_dir_path,
                                                         'fuzz_targets'))
    status_dir = os.path.join(output_dir_path, 'status')
    result_data = None
    result_file_path = None

    # Status files are in subdirectories like status/01, status/02, etc.
    if os.path.isdir(status_dir):
      for status_num in os.listdir(status_dir):
        status_num_path = os.path.join(status_dir, status_num)
        if not os.path.isdir(status_num_path):
          continue

        candidate_result_file = os.path.join(status_num_path, 'result.json')
        if os.path.isfile(candidate_result_file):
          try:
            with open(candidate_result_file, 'r') as f:
              result_data = json.load(f)
            result_file_path = candidate_result_file
            break
          except Exception as e:
            logger.warning('Failed to read result file %s: %s',
                           candidate_result_file, e)
            continue

    if result_data is None:
      if has_fuzz_targets:
        return {
            'status': 'partial',
            'output_dir': os.path.basename(output_dir_path),
            'has_fuzz_targets': True,
        }
      return {
          'status': 'empty',
          'output_dir': os.path.basename(output_dir_path),
          'has_fuzz_targets': False,
      }

    # A directory is considered completed only if it has generated fuzz target
    # artifacts and the stored result indicates the experiment actually ran.
    compiles = bool(result_data.get('compiles'))
    finished = bool(result_data.get('finished'))
    has_meaningful_result = compiles or finished or bool(
        result_data.get('coverage')) or bool(result_data.get('line_coverage_diff'))

    if has_fuzz_targets and has_meaningful_result:
      return {
          'status': 'completed',
          'output_dir': os.path.basename(output_dir_path),
          'result_file': result_file_path,
          'completion_time': os.path.getmtime(result_file_path),
          'completion_timestamp': datetime.fromtimestamp(
              os.path.getmtime(result_file_path)
          ).strftime('%Y-%m-%d %H:%M:%S'),
      }

    if has_fuzz_targets:
      return {
          'status': 'partial',
          'output_dir': os.path.basename(output_dir_path),
          'result_file': result_file_path,
          'has_fuzz_targets': True,
      }

    return {
        'status': 'empty',
        'output_dir': os.path.basename(output_dir_path),
        'result_file': result_file_path,
        'has_fuzz_targets': False,
    }

  def _has_artifacts(self, dir_path: str) -> bool:
    """Return True when a directory contains at least one non-hidden file."""
    if not os.path.isdir(dir_path):
      return False
    for entry in os.listdir(dir_path):
      if not entry.startswith('.'):
        return True
    return False

  def get_completed_benchmark_ids(self) -> List[str]:
    """Get list of completed benchmark IDs.
    
    Returns:
      List of benchmark IDs that are marked as completed
    """
    completed = self.scan_completed_experiments()
    return list(completed.keys())

  def is_completed(self, benchmark_id: str) -> bool:
    """Check if a specific benchmark is completed.
    
    Args:
      benchmark_id: Benchmark identifier
      
    Returns:
      True if completed, False otherwise
    """
    return benchmark_id in self.get_completed_benchmark_ids()

  def save_checkpoint(self, 
                     benchmark_id: str, 
                     status: str,
                     output_dir: Optional[str] = None,
                     result: Optional[Dict] = None) -> None:
    """Save a checkpoint for a benchmark.
    
    Args:
      benchmark_id: Benchmark identifier
      status: Status string ('completed', 'in_progress', 'error', 'pending')
      output_dir: Output directory name
      result: Optional result data
    """
    if benchmark_id not in self.registry:
      self.registry[benchmark_id] = {}
    
    checkpoint = {
        'status': status,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    if output_dir:
      checkpoint['output_dir'] = output_dir
    
    if result:
      if isinstance(result, str):
        checkpoint['error_message'] = result
      else:
        checkpoint['result'] = result

    self.registry[benchmark_id].update(checkpoint)
    self._save_registry()
    
    logger.debug(f'Saved checkpoint for {benchmark_id}: {status}')

  def print_status(self, verbose: bool = False) -> None:
    """Print status of all experiments.
    
    Args:
      verbose: If True, print detailed information
    """
    completed = self.get_completed_benchmark_ids()
    self.scan_completed_experiments()  # Ensure registry is up-to-date
    
    logger.info('=' * 80)
    logger.info('Experiment Status Summary')
    logger.info('=' * 80)
    
    total = len(self.registry)
    completed_count = len(completed)
    
    logger.info(f'Total experiments: {total}')
    logger.info(f'Completed: {completed_count}')
    logger.info(f'Pending/Error: {total - completed_count}')
    
    if verbose:
      logger.info('\nDetailed Status:')
      for benchmark_id, checkpoint in sorted(self.registry.items()):
        status = checkpoint.get('status', 'unknown')
        timestamp = checkpoint.get('timestamp', 'N/A')
        output_dir = checkpoint.get('output_dir', 'N/A')
        
        # Use emoji for visual indication
        status_icon = {
            'completed': '✓',
            'in_progress': '⏳',
            'error': '✗',
          'partial': '~',
          'empty': '-',
            'pending': '-',
        }.get(status, '?')
        
        logger.info(f'{status_icon} {benchmark_id:40} {status:12} {timestamp}')
        
        if status == 'error' and 'error_message' in checkpoint:
          error_msg = checkpoint['error_message']
          # Truncate long error messages
          if len(error_msg) > 60:
            error_msg = error_msg[:57] + '...'
          logger.info(f'  └─ Error: {error_msg}')

  def get_resume_info(self) -> Dict:
    """Get information for resume operation.
    
    Returns:
      Dict with 'completed' and 'pending' lists
    """
    self.scan_completed_experiments()
    completed = self.get_completed_benchmark_ids()
    pending = [bid for bid in self.registry.keys() if bid not in completed]
    
    return {
        'completed': completed,
        'completed_count': len(completed),
        'pending': pending,
        'pending_count': len(pending),
        'total': len(self.registry),
    }

  def mark_started(self, benchmark_id: str, output_dir: str) -> None:
    """Mark a benchmark as started.
    
    Args:
      benchmark_id: Benchmark identifier
      output_dir: Output directory name
    """
    self.save_checkpoint(benchmark_id, 'in_progress', output_dir)

  def mark_completed(self, benchmark_id: str, result: Optional[Dict] = None) -> None:
    """Mark a benchmark as completed.
    
    Args:
      benchmark_id: Benchmark identifier
      result: Optional result data
    """
    self.save_checkpoint(benchmark_id, 'completed', result=result)

  def mark_error(self, benchmark_id: str, error_message: str) -> None:
    """Mark a benchmark as errored.
    
    Args:
      benchmark_id: Benchmark identifier
      error_message: Error message
    """
    self.save_checkpoint(benchmark_id, 'error', result=error_message)
