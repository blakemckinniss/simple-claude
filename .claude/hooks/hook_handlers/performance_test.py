#!/usr/bin/env python3
"""
Performance test for UserPromptSubmit hook optimization.
"""

import time
import json
import subprocess
import sys
import os

def test_hook_performance(iterations=10):
    """Test hook performance over multiple iterations."""
    
    test_input = {
        "session_id": "perf_test",
        "transcript_path": "/tmp/test",
        "cwd": os.getcwd(),
        "hook_event_name": "UserPromptSubmit",
        "prompt": "analyze this performance optimization"
    }
    
    times = []
    
    for i in range(iterations):
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [sys.executable, 'UserPromptSubmit.py'],
                input=json.dumps(test_input),
                capture_output=True,
                text=True,
                timeout=5
            )
            
            end_time = time.time()
            execution_time = (end_time - start_time) * 1000  # Convert to ms
            times.append(execution_time)
            
            if result.returncode != 0:
                print(f"Error in iteration {i}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"Timeout in iteration {i}")
            times.append(5000)  # 5 second timeout
    
    # Calculate statistics
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    print(f"Performance Test Results ({iterations} iterations):")
    print(f"Average execution time: {avg_time:.1f}ms")
    print(f"Minimum execution time: {min_time:.1f}ms") 
    print(f"Maximum execution time: {max_time:.1f}ms")
    print(f"Target: <100ms - {'✓ PASS' if avg_time < 100 else '✗ FAIL'}")
    
    return avg_time < 100

if __name__ == "__main__":
    # Change to hook directory
    hook_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(hook_dir)
    
    success = test_hook_performance()
    sys.exit(0 if success else 1)