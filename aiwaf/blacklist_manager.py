# aiwaf/blacklist_manager.py

from .storage import get_blacklist_store, get_exemption_store

class BlacklistManager:
    @staticmethod
    def block(ip, reason):
        """Add IP to blacklist, but only if it's not exempted"""
        # Check if IP is exempted before blocking
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return  # Don't block exempted IPs
        
        store = get_blacklist_store()
        store.block_ip(ip, reason)

    @staticmethod
    def is_blocked(ip):
        """Check if IP is blocked, but respect exemptions"""
        # First check if IP is exempted - exemptions override blacklist
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return False  # Exempted IPs are never considered blocked
        
        # If not exempted, check blacklist
        store = get_blacklist_store()
        return store.is_blocked(ip)

    @staticmethod
    def all_blocked():
        store = get_blacklist_store()
        return store.get_all_blocked_ips()
    
    @staticmethod
    def unblock(ip):
        store = get_blacklist_store()
        store.unblock_ip(ip)
