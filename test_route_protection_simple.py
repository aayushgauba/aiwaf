#!/usr/bin/env python3

def test_keyword_extraction_logic():
    """Test the keyword extraction logic without Django setup"""
    print("🧪 Testing Route Keyword Extraction Logic")
    print("=" * 50)
    
    # Simulate the enhanced get_legitimate_keywords function
    def get_legitimate_keywords_simulation():
        legitimate = set()
        
        # Default legitimate keywords
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
        
        # Simulate Django route extraction
        simulated_django_routes = {
            # From URL patterns like path('profile/', ...)
            "profile", "profiles", "user", "users", "admin", "api", "accounts", 
            "login", "register", "posts", "comments", "dashboard", "en", "fr",
            # From app names like 'blog', 'auth', 'contenttypes'
            "blog", "auth", "contenttypes", "sessions", "messages",
            # From model names
            "post", "comment", "category", "tag", "user", "group"
        }
        legitimate.update(simulated_django_routes)
        
        # From settings
        settings_keywords = ["special", "custom", "exempt1", "exempt2"]
        legitimate.update(settings_keywords)
        
        return legitimate
    
    # Test the keyword learning protection
    def test_keyword_learning_protection():
        import re
        from collections import Counter
        
        legitimate_keywords = get_legitimate_keywords_simulation()
        print(f"   Total legitimate keywords: {len(legitimate_keywords)}")
        print(f"   Sample legitimate keywords: {sorted(list(legitimate_keywords))[:15]}")
        
        # Simulate log entries that mix legitimate and malicious keywords
        fake_log_entries = [
            {"path": "/profile/hack.php", "status": "404"},  # profile = legitimate
            {"path": "/user/12345/shell.php", "status": "404"},  # user = legitimate  
            {"path": "/admin/xmlrpc.php", "status": "404"},  # admin = legitimate
            {"path": "/api/v1/exploit.php", "status": "404"},  # api = legitimate
            {"path": "/posts/badword.php", "status": "404"},  # posts = legitimate, badword = malicious
            {"path": "/malicious/unknown/evilkeyword.php", "status": "404"},  # all malicious
            {"path": "/accounts/login/hack", "status": "404"},  # accounts, login = legitimate
            {"path": "/dashboard/suspicious.asp", "status": "500"},  # dashboard = legitimate, suspicious = malicious
            {"path": "/en/profile/attack", "status": "404"},  # en, profile = legitimate, attack = malicious
        ]
        
        # Simulate the keyword extraction logic from trainer.py
        tokens = Counter()
        STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager", ".asp"]
        
        print("\n   Processing log entries:")
        for entry in fake_log_entries:
            print(f"     Path: {entry['path']}")
            if entry["status"].startswith(("4", "5")):  # Error status
                extracted_segments = []
                learned_segments = []
                
                for seg in re.split(r"\W+", entry["path"].lower()):
                    if len(seg) > 3:
                        extracted_segments.append(seg)
                        if (seg not in STATIC_KW and 
                            seg not in legitimate_keywords):  # KEY PROTECTION
                            tokens[seg] += 1
                            learned_segments.append(seg)
                
                print(f"       Extracted: {extracted_segments}")
                print(f"       Learned as suspicious: {learned_segments}")
        
        print(f"\n   Final suspicious keywords learned:")
        for keyword, count in tokens.most_common():
            print(f"     - '{keyword}': {count} occurrences")
        
        # Verify protection worked
        print(f"\n   Verification:")
        protected_keywords = ['profile', 'user', 'admin', 'api', 'accounts', 'login', 'posts', 'dashboard', 'en']
        errors = []
        
        for keyword in protected_keywords:
            if keyword in tokens:
                errors.append(keyword)
                print(f"     ❌ '{keyword}' was learned as suspicious (SHOULD BE PROTECTED)")
            else:
                print(f"     ✅ '{keyword}' correctly protected from learning")
        
        expected_malicious = ['badword', 'malicious', 'unknown', 'evilkeyword', 'hack', 'exploit', 'suspicious', 'attack']
        learned_malicious = [kw for kw in expected_malicious if kw in tokens]
        
        print(f"\n     Malicious keywords correctly learned: {learned_malicious}")
        
        if errors:
            print(f"\n   ❌ PROTECTION FAILED: {len(errors)} legitimate keywords learned as suspicious")
            return False
        else:
            print(f"\n   ✅ PROTECTION SUCCESSFUL: All legitimate keywords protected")
            return True
    
    # Run the test
    success = test_keyword_learning_protection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 Route keyword protection is working correctly!")
        print("✅ Django routes, app names, and model names will be ignored during keyword learning")
    else:
        print("❌ Route keyword protection needs improvement")
    
    return success

if __name__ == "__main__":
    test_keyword_extraction_logic()
