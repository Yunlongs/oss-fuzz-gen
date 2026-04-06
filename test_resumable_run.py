#!/usr/bin/env python3
"""
Test script for resumable run functionality.

This script tests the checkpoint manager and resume functionality
without actually running expensive LLM experiments.
"""

import os
import sys
import json
import shutil
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checkpoint_manager import CheckpointManager
from experiment.benchmark import Benchmark


def setup_test_environment():
    """Create a test environment with mock output directories."""
    test_dir = tempfile.mkdtemp(prefix='resumable_test_')
    print(f"✓ Created test directory: {test_dir}")
    return test_dir


def create_mock_experiment(work_dir, project, function_name, status_content=None):
    """Create a mock completed experiment output."""
    dir_name = f"output-{project}-{function_name}"
    output_dir = os.path.join(work_dir, dir_name)
    status_dir = os.path.join(output_dir, 'status', '01')
    
    os.makedirs(status_dir, exist_ok=True)
    
    # Create mock result.json
    result_file = os.path.join(status_dir, 'result.json')
    result_data = status_content or {
        'project': project,
        'function_signature': f'void {function_name}()',
        'trial': 1,
        'compiles': True,
        'crashes': False,
    }
    
    with open(result_file, 'w') as f:
        json.dump(result_data, f)
    
    print(f"✓ Created mock experiment: {dir_name}")
    return output_dir


def test_basic_scan():
    """Test 1: Basic scanning of completed experiments."""
    print("\n" + "="*60)
    print("Test 1: Basic Scanning")
    print("="*60)
    
    test_dir = setup_test_environment()
    
    try:
        # Create some mock experiments
        create_mock_experiment(test_dir, 'file', 'magic_open')
        create_mock_experiment(test_dir, 'file', 'magic_close')
        create_mock_experiment(test_dir, 'file', 'magic_load')
        
        # Initialize checkpoint manager
        cm = CheckpointManager(test_dir)
        
        # Scan completed experiments
        completed = cm.scan_completed_experiments()
        
        assert len(completed) == 3, f"Expected 3 completed, got {len(completed)}"
        print(f"✓ Found {len(completed)} completed experiments")
        
        for bid in completed:
            print(f"  - {bid}: {completed[bid]['status']}")
        
        print("\n✅ Test 1 PASSED")
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_resume_info():
    """Test 2: Resume information calculation."""
    print("\n" + "="*60)
    print("Test 2: Resume Information")
    print("="*60)
    
    test_dir = setup_test_environment()
    
    try:
        # Create completed experiments
        for i in range(5):
            create_mock_experiment(test_dir, 'file', f'func_{i}')
        
        # Create some pending entries manually
        cm = CheckpointManager(test_dir)
        cm.save_checkpoint('file-func_pending_1', 'pending')
        cm.save_checkpoint('file-func_pending_2', 'pending')
        
        # Get resume info
        resume_info = cm.get_resume_info()
        
        assert resume_info['completed_count'] == 5, f"Expected 5 completed, got {resume_info['completed_count']}"
        assert resume_info['pending_count'] == 2, f"Expected 2 pending, got {resume_info['pending_count']}"
        assert resume_info['total'] == 7, f"Expected 7 total, got {resume_info['total']}"
        
        print(f"✓ Completed: {resume_info['completed_count']}")
        print(f"✓ Pending: {resume_info['pending_count']}")
        print(f"✓ Total: {resume_info['total']}")
        
        print("\n✅ Test 2 PASSED")
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_checkpoint_persistence():
    """Test 3: Checkpoint persistence across instances."""
    print("\n" + "="*60)
    print("Test 3: Checkpoint Persistence")
    print("="*60)
    
    test_dir = setup_test_environment()
    
    try:
        # Create first checkpoint manager instance
        cm1 = CheckpointManager(test_dir)
        cm1.mark_completed('file-test1')
        cm1.mark_error('file-test2', 'Network error')
        
        # Verify registry was saved
        registry_path = os.path.join(test_dir, '.checkpoint_registry.json')
        assert os.path.exists(registry_path), "Registry file not created"
        print(f"✓ Registry file created: {registry_path}")
        
        # Load registry in new instance
        cm2 = CheckpointManager(test_dir)
        
        assert 'file-test1' in cm2.registry, "Completed task not in new instance"
        assert cm2.registry['file-test1']['status'] == 'completed'
        
        assert 'file-test2' in cm2.registry, "Error task not in new instance"
        assert cm2.registry['file-test2']['status'] == 'error'
        assert 'Network error' in cm2.registry['file-test2']['error_message']
        
        print("✓ Registry persisted correctly")
        print(f"  - file-test1: {cm2.registry['file-test1']['status']}")
        print(f"  - file-test2: {cm2.registry['file-test2']['status']}")
        
        print("\n✅ Test 3 PASSED")
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_is_completed():
    """Test 4: is_completed() method."""
    print("\n" + "="*60)
    print("Test 4: is_completed() Method")
    print("="*60)
    
    test_dir = setup_test_environment()
    
    try:
        # Create mock experiment
        create_mock_experiment(test_dir, 'file', 'magic_open')
        
        cm = CheckpointManager(test_dir)
        
        # Test with completed benchmark
        result1 = cm.is_completed('file-magic_open')
        assert result1 == True, "Should be completed"
        print("✓ is_completed('file-magic_open') = True")
        
        # Test with non-completed benchmark
        result2 = cm.is_completed('file-magic_nonexistent')
        assert result2 == False, "Should not be completed"
        print("✓ is_completed('file-magic_nonexistent') = False")
        
        print("\n✅ Test 4 PASSED")
        return True
        
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_file_project_scanning():
    """Test 5: Real file project scanning."""
    print("\n" + "="*60)
    print("Test 5: Real File Project Scanning")
    print("="*60)
    
    file_output_dir = '/home/lyuyunlong/work/oss-fuzz-gen/output/file'
    
    if not os.path.exists(file_output_dir):
        print(f"⚠ Skip: {file_output_dir} not found")
        return True
    
    try:
        cm = CheckpointManager(file_output_dir)
        completed = cm.scan_completed_experiments()
        
        print(f"✓ Found {len(completed)} completed experiments in file project")
        
        if len(completed) > 0:
            resume_info = cm.get_resume_info()
            print(f"  - Completed: {resume_info['completed_count']}")
            print(f"  - Pending: {resume_info['pending_count']}")
            print(f"  - Total: {resume_info['total']}")
            
            # Show first few
            for bid in sorted(completed.keys())[:3]:
                ts = completed[bid].get('completion_timestamp', 'N/A')
                print(f"  - {bid}: {ts}")
        
        print("\n✅ Test 5 PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Test 5 FAILED: {e}")
        return False


def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("Running Resumable Run Tests")
    print("="*60)
    
    tests = [
        test_basic_scan,
        test_resume_info,
        test_checkpoint_persistence,
        test_is_completed,
        test_file_project_scanning,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append((test_func.__name__, result))
        except Exception as e:
            print(f"\n❌ {test_func.__name__} FAILED with exception:")
            print(f"   {e}")
            import traceback
            traceback.print_exc()
            results.append((test_func.__name__, False))
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:8} {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return passed == total


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
