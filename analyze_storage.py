#!/usr/bin/env python3
"""
Simple diagnostic script to check AIWAF keyword storage without Django.
This analyzes the code structure to identify potential issues.
"""

import os
import sys
import re

def analyze_storage_code():
    """Analyze the storage.py file for potential issues"""
    print("=== AIWAF Storage Code Analysis ===\n")
    
    storage_path = os.path.join(os.path.dirname(__file__), 'aiwaf', 'storage.py')
    if not os.path.exists(storage_path):
        print(f"Error: {storage_path} not found")
        return
    
    with open(storage_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check 1: Global variable initialization
    print("1. Checking global variable initialization:")
    if "FeatureSample = BlacklistEntry = IPExemption = DynamicKeyword = None" in content:
        print("   ✓ Models initialized as None (deferred import pattern)")
    else:
        print("   ✗ Models not properly initialized")
    print()
    
    # Check 2: _import_models function
    print("2. Analyzing _import_models function:")
    import_models_match = re.search(r'def _import_models\(\):(.*?)(?=def|\Z)', content, re.DOTALL)
    if import_models_match:
        function_body = import_models_match.group(1)
        
        if "apps.ready" in function_body:
            print("   ✓ Checks for apps.ready")
        else:
            print("   ✗ Missing apps.ready check")
            
        if "apps.is_installed" in function_body:
            print("   ⚠ Uses apps.is_installed('aiwaf') - this can fail if app name differs")
        else:
            print("   ? No specific app installation check")
            
        if "try:" in function_body and "except" in function_body:
            print("   ✓ Has exception handling")
        else:
            print("   ✗ Missing exception handling")
    print()
    
    # Check 3: add_keyword method
    print("3. Analyzing add_keyword method:")
    add_keyword_match = re.search(r'def add_keyword\(.*?\):(.*?)(?=def|\Z)', content, re.DOTALL)
    if add_keyword_match:
        method_body = add_keyword_match.group(1)
        
        if "if DynamicKeyword is None:" in method_body:
            print("   ✓ Checks if DynamicKeyword is None")
            if "return" in method_body.split("if DynamicKeyword is None:")[1].split('\n')[1]:
                print("   ⚠ Returns silently when models unavailable")
            else:
                print("   ✓ Provides feedback when models unavailable")
        else:
            print("   ✗ Missing None check for DynamicKeyword")
            
        if "get_or_create" in method_body:
            print("   ✓ Uses get_or_create for database operations")
        else:
            print("   ✗ Not using get_or_create")
    print()
    
    # Check 4: Middleware usage
    print("4. Checking middleware usage:")
    middleware_path = os.path.join(os.path.dirname(__file__), 'aiwaf', 'middleware.py')
    if os.path.exists(middleware_path):
        with open(middleware_path, 'r', encoding='utf-8') as f:
            middleware_content = f.read()
        
        add_keyword_calls = re.findall(r'keyword_store\.add_keyword\([^)]+\)', middleware_content)
        print(f"   Found {len(add_keyword_calls)} calls to keyword_store.add_keyword()")
        for i, call in enumerate(add_keyword_calls[:3], 1):  # Show first 3
            print(f"   {i}. {call}")
        if len(add_keyword_calls) > 3:
            print(f"   ... and {len(add_keyword_calls) - 3} more")
    else:
        print("   ✗ middleware.py not found")
    print()
    
    # Check 5: Potential issues summary
    print("5. Potential Issues Summary:")
    issues = []
    
    if "apps.is_installed('aiwaf')" in content:
        issues.append("⚠ Hard-coded 'aiwaf' app name check may fail in different installations")
    
    if 'return' in content and 'if DynamicKeyword is None:' in content:
        silent_return = True
        for line in content.split('\n'):
            if 'if DynamicKeyword is None:' in line:
                # Check next few lines for silent return
                idx = content.split('\n').index(line)
                next_lines = content.split('\n')[idx+1:idx+5]
                for next_line in next_lines:
                    if 'print(' in next_line or 'log' in next_line.lower():
                        silent_return = False
                        break
                    elif 'return' in next_line.strip():
                        break
        if silent_return:
            issues.append("⚠ Silent failure when models unavailable - no error logging")
    
    if not issues:
        print("   ✓ No obvious issues detected")
    else:
        for issue in issues:
            print(f"   {issue}")
    
    print("\n=== Analysis Complete ===")
    
    # Provide recommendations
    print("\nRecommendations:")
    print("1. Add error logging to _import_models() for debugging")
    print("2. Make model import more flexible (don't rely on exact app name)")
    print("3. Add warning messages when keyword storage fails")
    print("4. Consider fallback storage mechanism if Django models unavailable")

if __name__ == "__main__":
    analyze_storage_code()
