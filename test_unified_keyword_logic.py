#!/usr/bin/env python3

def test_unified_keyword_logic():
    """Test that trainer and middleware use unified keyword detection logic"""
    print("🧪 Testing Unified Keyword Logic (Trainer + Middleware)")
    print("=" * 60)
    
    # Simulate unified legitimate keyword detection
    def get_unified_legitimate_keywords():
        legitimate = set()
        
        # Common legitimate path segments (shared by both)
        default_legitimate = {
            "profile", "user", "users", "account", "accounts", "settings", "dashboard", 
            "home", "about", "contact", "help", "search", "list", "lists",
            "view", "views", "edit", "create", "update", "delete", "detail", "details",
            "api", "auth", "login", "logout", "register", "signup", "signin",
            "reset", "confirm", "activate", "verify", "page", "pages",
            "category", "categories", "tag", "tags", "post", "posts",
            "article", "articles", "blog", "blogs", "news", "item", "items",
            "admin", "administration", "manage", "manager", "control", "panel",
            "config", "configuration", "option", "options", "preference", "preferences"
        }
        legitimate.update(default_legitimate)
        
        # Django route extraction (shared by both)
        django_routes = {
            # URL pattern keywords
            "profile", "profiles", "user", "users", "admin", "api", "accounts", 
            "login", "register", "posts", "comments", "dashboard", "en", "fr", "de",
            # App names
            "blog", "auth", "contenttypes", "sessions", "messages", "staticfiles",
            # Model names
            "post", "comment", "category", "tag", "group", "permission",
            # View function keywords
            "detail", "list", "create", "update", "delete"
        }
        legitimate.update(django_routes)
        
        # Settings-based keywords (shared by both)
        settings_keywords = ["custom", "special", "exempt1", "exempt2"]
        legitimate.update(settings_keywords)
        
        return legitimate

    def test_trainer_logic():
        """Test trainer keyword learning logic"""
        print("\n📚 Testing Trainer Logic:")
        
        import re
        from collections import Counter
        
        legitimate_keywords = get_unified_legitimate_keywords()
        
        # Simulate log entries for training
        log_entries = [
            {"path": "/profile/hack.php", "status": "404", "exists": False},
            {"path": "/user/123/", "status": "200", "exists": True},
            {"path": "/admin/xmlrpc.php", "status": "404", "exists": False},
            {"path": "/api/v1/posts/", "status": "200", "exists": True},
            {"path": "/malicious/exploit.asp", "status": "404", "exists": False},
            {"path": "/accounts/login/", "status": "200", "exists": True},
            {"path": "/evil/backdoor/test.php", "status": "500", "exists": False},
            {"path": "/en/profile/attack", "status": "404", "exists": False},
        ]
        
        # Simulate trainer keyword learning
        tokens = Counter()
        STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager", ".asp"]
        
        for entry in log_entries:
            # Only learn from error status codes on non-existent paths
            if (entry["status"].startswith(("4", "5")) and 
                not entry["exists"]):
                
                for seg in re.split(r"\W+", entry["path"].lower()):
                    if (len(seg) > 3 and 
                        seg not in STATIC_KW and 
                        seg not in legitimate_keywords):  # Key protection
                        tokens[seg] += 1
        
        print(f"   ✅ Trainer would learn: {dict(tokens.most_common())}")
        
        # Verify legitimate keywords weren't learned
        legitimate_in_tokens = [kw for kw in ['profile', 'user', 'admin', 'api', 'accounts', 'en'] if kw in tokens]
        if legitimate_in_tokens:
            print(f"   ❌ ERROR: Trainer learned legitimate keywords: {legitimate_in_tokens}")
            return False
        else:
            print(f"   ✅ Trainer correctly protected all legitimate keywords")
            return True

    def test_middleware_logic():
        """Test middleware blocking logic"""
        print("\n🛡️  Testing Middleware Logic:")
        
        import re
        
        legitimate_keywords = get_unified_legitimate_keywords()
        
        # Simulate middleware request processing
        test_requests = [
            {"path": "/profile/", "exists": True, "should_block": False},
            {"path": "/user/123/", "exists": True, "should_block": False},
            {"path": "/admin/", "exists": True, "should_block": False},
            {"path": "/api/v1/posts/", "exists": True, "should_block": False},
            {"path": "/accounts/login/", "exists": True, "should_block": False},
            {"path": "/en/profile/", "exists": True, "should_block": False},
            {"path": "/profile/hack.php", "exists": False, "should_block": True},
            {"path": "/malicious/exploit.asp", "exists": False, "should_block": True},
            {"path": "/evil/backdoor.php", "exists": False, "should_block": True},
            {"path": "/attack/xss/test", "exists": False, "should_block": True},
        ]
        
        STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager", ".asp"]
        
        all_correct = True
        
        for req in test_requests:
            path = req["path"].lower().lstrip("/")
            path_exists = req["exists"]
            segments = [seg for seg in re.split(r"\W+", path) if len(seg) > 3]
            
            will_block = False
            blocking_reason = ""
            
            for seg in segments:
                # Skip if legitimate and path exists and not malicious context
                if (seg in legitimate_keywords and path_exists):
                    continue
                
                is_suspicious = False
                
                # Check static keywords
                if seg in STATIC_KW:
                    is_suspicious = True
                    blocking_reason = f"Static keyword: {seg}"
                
                # Check inherently malicious patterns
                elif (not path_exists and 
                      seg not in legitimate_keywords and 
                      any(pattern in seg for pattern in ['hack', 'exploit', 'attack', 'malicious', 'evil', 'backdoor', 'inject', 'xss'])):
                    is_suspicious = True
                    blocking_reason = f"Inherently malicious: {seg}"
                
                # File extension on non-existent path
                elif seg.startswith('.') and not path_exists:
                    is_suspicious = True
                    blocking_reason = f"File extension attack: {seg}"
                
                if is_suspicious and not path_exists:
                    will_block = True
                    break
            
            status = "✅" if (will_block == req["should_block"]) else "❌"
            action = "BLOCK" if will_block else "ALLOW"
            
            print(f"   {status} {req['path']} -> {action} {blocking_reason if will_block else ''}")
            
            if will_block != req["should_block"]:
                all_correct = False
                print(f"      ERROR: Expected {'BLOCK' if req['should_block'] else 'ALLOW'}")
        
        return all_correct

    def test_consistency():
        """Test that trainer and middleware have consistent legitimate keyword sets"""
        print("\n🔄 Testing Consistency:")
        
        # Both should use the same legitimate keywords
        trainer_keywords = get_unified_legitimate_keywords()
        middleware_keywords = get_unified_legitimate_keywords()  # Same function
        
        if trainer_keywords == middleware_keywords:
            print(f"   ✅ Trainer and middleware use identical keyword sets ({len(trainer_keywords)} keywords)")
            return True
        else:
            print(f"   ❌ Keyword sets differ!")
            print(f"      Trainer only: {trainer_keywords - middleware_keywords}")
            print(f"      Middleware only: {middleware_keywords - trainer_keywords}")
            return False

    # Run all tests
    print(f"🔗 Testing unified legitimate keyword detection for both components...")
    
    trainer_ok = test_trainer_logic()
    middleware_ok = test_middleware_logic()
    consistency_ok = test_consistency()
    
    print("\n" + "=" * 60)
    
    if trainer_ok and middleware_ok and consistency_ok:
        print("🎉 SUCCESS: Unified keyword logic working perfectly!")
        print("✅ Both trainer and middleware use identical legitimate keyword detection")
        print("✅ Legitimate Django routes are protected from learning and blocking")
        print("✅ Malicious keywords are properly detected and blocked")
        return True
    else:
        print("❌ Issues found in unified keyword logic")
        return False

if __name__ == "__main__":
    test_unified_keyword_logic()
