# aiwaf/blacklist_manager.py

from .storage import get_blacklist_store

class BlacklistManager:
    @staticmethod
    def block(ip, reason):
        store = get_blacklist_store()
        store.add_ip(ip, reason)

    @staticmethod
    def is_blocked(ip):
        store = get_blacklist_store()
        return store.is_blocked(ip)

    @staticmethod
    def all_blocked():
        store = get_blacklist_store()
        return store.get_all()
    
    @staticmethod
    def unblock(ip):
        store = get_blacklist_store()
        store.remove_ip(ip)
