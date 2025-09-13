#!/usr/bin/env python3
"""
Mass Conversion Script for AIWAF Tests to Django Unit Tests

This script converts all remaining standalone test files to proper Django unit tests.
"""

import os
import sys
import re
from pathlib import Path

# Template for Django unit tests
DJANGO_TEST_TEMPLATE = '''#!/usr/bin/env python3
"""
Django Unit Test for {test_name}

{test_description}
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import {base_class}


class {class_name}(base_class):
    """Test {test_name} functionality"""
    
    def setUp(self):
        super().setUp()
        # Import after Django setup
        {setup_imports}
    
    {test_methods}


if __name__ == "__main__":
    import unittest
    unittest.main()
'''

def determine_base_class(file_content, filename):
    """Determine the appropriate base class based on file content"""
    if 'middleware' in filename.lower() or 'header' in filename.lower():
        return 'AIWAFMiddlewareTestCase'
    elif 'storage' in filename.lower() or 'database' in filename.lower():
        return 'AIWAFStorageTestCase'
    elif 'trainer' in filename.lower() or 'keyword' in filename.lower():
        return 'AIWAFTrainerTestCase'
    else:
        return 'AIWAFTestCase'

def extract_test_functions(file_content):
    """Extract test functions from existing file"""
    test_functions = []
    
    # Find function definitions
    function_pattern = r'def\s+(test_\w+|.*test.*)\s*\([^)]*\):'
    matches = re.finditer(function_pattern, file_content, re.MULTILINE)
    
    for match in matches:
        func_name = match.group(1)
        if not func_name.startswith('test_'):
            func_name = f'test_{func_name}'
        
        test_functions.append(func_name)
    
    return test_functions

def generate_test_methods(test_functions, filename):
    """Generate Django test methods"""
    methods = []
    
    for func_name in test_functions:
        method_template = f'''def {func_name}(self):
        """Test {func_name.replace('test_', '').replace('_', ' ')}"""
        # TODO: Convert original test logic to Django test
        # Original test: {func_name}
        
        # Placeholder test - replace with actual logic
        self.assertTrue(True, "Test needs implementation")
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    '''
        methods.append(method_template)
    
    return '\n    '.join(methods)

def convert_test_file(file_path):
    """Convert a single test file to Django unit test"""
    filename = os.path.basename(file_path)
    
    # Skip files that are already converted or are config files
    if ('_django' in filename or 
        filename in ['base_test.py', 'test_settings.py', 'test_urls.py', 'README.md']):
        return None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return None
    
    # Extract information
    test_name = filename.replace('test_', '').replace('.py', '').replace('_', ' ').title()
    class_name = ''.join(word.capitalize() for word in filename.replace('test_', '').replace('.py', '').split('_')) + 'TestCase'
    base_class = determine_base_class(content, filename)
    
    # Extract existing test functions
    test_functions = extract_test_functions(content)
    
    if not test_functions:
        # Create a default test if no functions found
        test_functions = ['test_basic_functionality']
    
    # Generate setup imports based on file type
    setup_imports = "# Add imports as needed"
    if 'middleware' in filename:
        setup_imports = "# from aiwaf.middleware import MiddlewareClass"
    elif 'storage' in filename:
        setup_imports = "# from aiwaf.storage import Storage"
    elif 'trainer' in filename:
        setup_imports = "# from aiwaf.trainer import Trainer"
    
    # Generate test methods
    test_methods = generate_test_methods(test_functions, filename)
    
    # Extract description from docstring if available
    docstring_match = re.search(r'"""([^"]+)"""', content)
    test_description = docstring_match.group(1).strip() if docstring_match else f"Tests for {test_name}"
    
    # Generate the new Django test file
    django_test_content = DJANGO_TEST_TEMPLATE.format(
        test_name=test_name,
        test_description=test_description,
        base_class=base_class,
        class_name=class_name,
        setup_imports=setup_imports,
        test_methods=test_methods
    )
    
    # Create new filename
    new_filename = filename.replace('.py', '_django.py')
    new_file_path = os.path.join(os.path.dirname(file_path), new_filename)
    
    return new_file_path, django_test_content

def main():
    """Main conversion function"""
    tests_dir = Path(__file__).parent
    
    print("🔄 Converting AIWAF Tests to Django Unit Tests")
    print("=" * 50)
    
    test_files = list(tests_dir.glob('test_*.py'))
    converted_count = 0
    
    for test_file in test_files:
        result = convert_test_file(test_file)
        
        if result:
            new_file_path, content = result
            
            try:
                with open(new_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"✅ Converted: {test_file.name} → {os.path.basename(new_file_path)}")
                converted_count += 1
                
            except Exception as e:
                print(f"❌ Error writing {new_file_path}: {e}")
        else:
            print(f"⏭️  Skipped: {test_file.name}")
    
    print(f"\n🎉 Conversion complete! Converted {converted_count} test files.")
    print("\n📋 Next steps:")
    print("1. Review generated Django test files")
    print("2. Implement actual test logic in TODO sections")
    print("3. Run tests with: python manage.py test")
    print("4. Update imports and assertions as needed")

if __name__ == "__main__":
    main()