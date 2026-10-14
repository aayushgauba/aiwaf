#!/usr/bin/env python3
"""
AIWAF CLI Consistency Test

This script demonstrates that the CLI now provides consistent results
regardless of the working directory.
"""

import subprocess
import os
from pathlib import Path

def run_cli_command(command, working_dir=None):
    """Run AIWAF CLI command and capture output."""
    full_command = [
        'python', '-m', 'aiwaf.flask.cli'
    ] + command.split()
    
    try:
        result = subprocess.run(
            full_command,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1

def test_directory_consistency():
    """Test that CLI gives consistent results from different directories."""
    
    print(" AIWAF CLI Directory Consistency Test")
    print("=" * 50)
    
    # Test directories
    test_dirs = [
        Path.cwd(),  # Current project directory
        Path.home(),  # User home directory
        Path("C:/") if os.name == 'nt' else Path("/"),  # Root directory
        Path.cwd().parent,  # Parent directory
    ]
    
    # Add some test data first
    print(" Adding test data...")
    stdout, stderr, code = run_cli_command("add allowlist 203.0.113.1")
    if code == 0:
        print(" Test data added successfully")
    else:
        print(f" Failed to add test data: {stderr}")
    
    print("\n Testing CLI from different directories:")
    print("-" * 50)
    
    data_directories = []
    outputs = []
    
    for i, test_dir in enumerate(test_dirs):
        if not test_dir.exists():
            continue
            
        print(f"\n Test {i+1}: Running from {test_dir}")
        
        try:
            stdout, stderr, code = run_cli_command("list all", working_dir=str(test_dir))
            
            if code == 0:
                # Extract data directory from output
                for line in stdout.split('\n'):
                    if 'Auto-configured data directory:' in line:
                        data_dir = line.split(':', 1)[1].strip()
                        data_directories.append(data_dir)
                        print(f"    Data directory: {data_dir}")
                        break
                
                # Extract allowlist count
                for line in stdout.split('\n'):
                    if 'Allowlisted IPs' in line:
                        print(f"    {line}")
                        break
                        
                outputs.append(stdout)
                print("    Command successful")
            else:
                print(f"    Command failed: {stderr}")
                
        except Exception as e:
            print(f"    Error: {e}")
    
    # Analysis
    print(f"\n Analysis:")
    print("-" * 30)
    
    if len(set(data_directories)) == 1:
        print(" CONSISTENT: All commands used the same data directory")
        print(f" Data directory: {data_directories[0]}")
    else:
        print(" INCONSISTENT: Different data directories found:")
        for i, data_dir in enumerate(data_directories):
            print(f"   {i+1}. {data_dir}")
    
    # Check if outputs are similar (allowlist counts should match)
    allowlist_counts = []
    for output in outputs:
        for line in output.split('\n'):
            if 'Allowlisted IPs' in line and '(' in line:
                count = line.split('(')[1].split(')')[0]
                allowlist_counts.append(count)
                break
    
    if len(set(allowlist_counts)) <= 1:
        print(" CONSISTENT: All commands returned the same data")
    else:
        print(" INCONSISTENT: Different data returned from different directories")
    
    print(f"\n Result: {'PASS' if len(set(data_directories)) == 1 and len(set(allowlist_counts)) <= 1 else 'FAIL'}")

if __name__ == '__main__':
    test_directory_consistency()