#!/usr/bin/env python3
"""
Test setup.py configuration for AIWAF Flask dependencies.
"""
import ast

def test_setup_py():
    """Test that setup.py has correct dependency configuration."""
    print(" Testing setup.py Configuration")
    print("=" * 35)
    
    # Read setup.py to verify configuration
    try:
        with open('setup.py', 'r') as f:
            content = f.read()
        
        print(" setup.py file found")
        
        # Validate current package extras layout
        assert '"flask":' in content
        assert '"fastapi":' in content
        assert '"django":' in content
        setup_call = next(node for node in ast.walk(ast.parse(content))
                          if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'setup')
        required = ast.literal_eval(next(item.value for item in setup_call.keywords if item.arg == 'install_requires'))
        assert 'aiwaf-rust>=0.2.4' in required
        
        print(" setup.py configuration is correct")
        assert True
        
    except FileNotFoundError:
        print(" setup.py not found")
        raise AssertionError("setup.py not found")
    except Exception as e:
        print(f" Error reading setup.py: {e}")
        raise

def test_pyproject_toml():
    """Test that pyproject.toml has correct dependency configuration."""
    print("\n Testing pyproject.toml Configuration")
    print("=" * 40)
    
    try:
        with open('pyproject.toml', 'r') as f:
            content = f.read()
        
        # Validate current optional dependencies layout
        assert '[project.optional-dependencies]' in content
        assert 'flask =' in content
        assert 'fastapi =' in content
        assert 'django =' in content
        assert 'rust =' in content
        assert 'aiwaf-rust>=' in content
        
        print(" pyproject.toml configuration is correct")
        assert True
        
    except FileNotFoundError:
        print(" pyproject.toml not found")
        raise AssertionError("pyproject.toml not found")
    except Exception as e:
        print(f" Error reading pyproject.toml: {e}")
        raise

def show_installation_commands():
    """Show the installation commands that users can use."""
    print("\n Available Installation Commands")
    print("=" * 35)
    
    commands = [
        ("Basic installation", "pip install aiwaf-flask"),
        ("With AI features", "pip install aiwaf-flask[ai]"),
        ("Full installation", "pip install aiwaf-flask[all]"),
        ("Development mode", "pip install -e ."),
        ("AI only (existing install)", "pip install numpy>=1.20.0 scikit-learn>=1.0.0"),
    ]
    
    for description, command in commands:
        print(f"  {description:25}  {command}")

def main():
    """Run all configuration tests."""
    print(" AIWAF Flask Setup Configuration Test")
    print("=" * 45)
    
    setup_ok = test_setup_py()
    toml_ok = test_pyproject_toml()
    
    print("\n Configuration Test Summary:")
    print(f"setup.py: {' PASS' if setup_ok else ' FAIL'}")
    print(f"pyproject.toml: {' PASS' if toml_ok else ' FAIL'}")
    
    if setup_ok and toml_ok:
        print("\n All configuration tests passed!")
        print(" AI dependencies are properly configured")
        print(" Multiple installation options available")
    else:
        print("\n Configuration issues found")
    
    show_installation_commands()
    
    print("\n Dependency Groups:")
    print("  ai:  NumPy + Scikit-learn (ML features)")
    print("  dev: Testing and development tools")  
    print("  all: AI + development dependencies")

if __name__ == '__main__':
    main()
