# aiwaf/blacklist_manager.py

from django.conf import settings
from .storage import get_blacklist_store
from .utils import is_ip_exempted

class BlacklistManager:
    @staticmethod
    def block(ip, reason):
        """Add IP to blacklist, but only if it's not exempted"""
        if not getattr(settings, "AIWAF_ENABLE_IP_BLOCKING", True):
            return
        # Check if IP is exempted before blocking
        if is_ip_exempted(ip):
            return  # Don't block exempted IPs
        
        store = get_blacklist_store()
        store.block_ip(ip, reason)

    @staticmethod
    def is_blocked(ip):
        """Check if IP is blocked, but respect exemptions"""
        if not getattr(settings, "AIWAF_ENABLE_IP_BLOCKING", True):
            return False
        # First check if IP is exempted - exemptions override blacklist
        if is_ip_exempted(ip):
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
