#!/usr/bin/env python3

def test_path_validation_flaw():
    """Test the path validation flaw scenario"""
    print("🧪 Testing Path Validation Flaw")
    print("=" * 50)
    
    # Simulate the current flawed logic
    def path_exists_in_django_flawed(path: str) -> bool:
        """Current implementation that has the flaw"""
        candidate = path.split("?")[0].lstrip("/")
        
        # Simulate Django URL resolution
        valid_paths = {
            "a",           # www.y.com/a/ is valid
            "profile",     # www.y.com/profile/ is valid
            "user",        # www.y.com/user/ is valid
            "admin"        # www.y.com/admin/ is valid
        }
        
        # Simulate the exact matching (this works correctly)
        if candidate in valid_paths:
            return True
            
        # Simulate prefix matching (this has the flaw)
        for valid_path in valid_paths:
            if candidate.startswith(valid_path):  # FLAW: /a/ would match /a
                return True
        
        return False
    
    # Enhanced logic that fixes the flaw
    def path_exists_in_django_fixed(path: str) -> bool:
        """Fixed implementation that handles trailing slashes correctly"""
        candidate = path.split("?")[0].strip("/")
        
        # Simulate Django URL resolution
        valid_paths = {
            "a",           # Exact match
            "profile",     # Exact match  
            "user",        # Exact match
            "admin"        # Exact match
        }
        
        valid_prefixes = {
            "api",         # /api/v1/, /api/users/, etc.
            "accounts",    # /accounts/login/, /accounts/register/, etc.
        }
        
        # Exact matching first
        if candidate in valid_paths:
            return True
            
        # For prefix matching, be more careful about path boundaries
        for prefix in valid_prefixes:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
        
        return False
    
    # Test cases that demonstrate the flaw
    test_cases = [
        # (path, should_exist, description)
        ("/a", True, "Base path exists"),
        ("/a/", False, "Trailing slash - might not exist"),
        ("/a/extra", False, "Extra path segment - doesn't exist"),
        ("/api", True, "API base exists"),
        ("/api/", True, "API with trailing slash exists"),
        ("/api/v1", True, "API subpath exists"),
        ("/api/v1/", True, "API subpath with trailing slash exists"),
        ("/profile", True, "Profile base exists"),
        ("/profile/", False, "Profile with trailing slash - might not exist"),
        ("/profile/123", False, "Profile with ID - doesn't exist"),
    ]
    
    print("\n   Testing Current (Flawed) Logic:")
    flawed_errors = 0
    for path, should_exist, description in test_cases:
        result = path_exists_in_django_flawed(path)
        status = "✅" if result == should_exist else "❌"
        if result != should_exist:
            flawed_errors += 1
        print(f"     {status} {path} -> {result} ({description})")
    
    print(f"\n   Flawed logic errors: {flawed_errors}")
    
    print("\n   Testing Fixed Logic:")
    fixed_errors = 0
    for path, should_exist, description in test_cases:
        result = path_exists_in_django_fixed(path)
        status = "✅" if result == should_exist else "❌" 
        if result != should_exist:
            fixed_errors += 1
        print(f"     {status} {path} -> {result} ({description})")
    
    print(f"\n   Fixed logic errors: {fixed_errors}")
    
    # Demonstrate the impact on keyword learning
    print("\n   Impact on Keyword Learning:")
    
    suspicious_requests = [
        {"path": "/a/hack.php", "status": "404"},      # /a/ doesn't exist, should learn 'hack'
        {"path": "/profile/exploit", "status": "404"}, # /profile/ doesn't exist, should learn 'exploit'  
        {"path": "/api/malicious", "status": "404"},   # /api/malicious doesn't exist, should learn 'malicious'
    ]
    
    print("\n     With Flawed Logic:")
    for req in suspicious_requests:
        path_exists = path_exists_in_django_flawed(req["path"])
        would_learn = not path_exists  # Only learn if path doesn't exist
        print(f"       {req['path']} -> exists: {path_exists}, would learn keywords: {would_learn}")
    
    print("\n     With Fixed Logic:")
    for req in suspicious_requests:
        path_exists = path_exists_in_django_fixed(req["path"])
        would_learn = not path_exists  # Only learn if path doesn't exist  
        print(f"       {req['path']} -> exists: {path_exists}, would learn keywords: {would_learn}")
    
    print("\n" + "=" * 50)
    if flawed_errors > fixed_errors:
        print("🔧 Fixed logic performs better - reduces false path validation")
    else:
        print("ℹ️  Both logics perform similarly on these test cases")

if __name__ == "__main__":
    test_path_validation_flaw()
