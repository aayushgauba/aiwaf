"""
Blocklist management system for AIWAF
"""
import time
import logging
from typing import Optional, Dict, Any, List
from .runtime_storage import get_blocklist_store, get_exemption_store
from .blocklist import should_block_ip

logger = logging.getLogger(__name__)


class BlocklistManager:
    """
    Centralized blocklist management system.
    
    This class provides a unified interface for blocking and unblocking IP addresses,
    with support for temporary and permanent blocks, exemption checking, and statistics.
    """
    
    @classmethod
    def block(
        cls,
        ip: str,
        reason: str,
        duration: Optional[int] = None,
        extended_request_info: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking  
            duration: Block duration in seconds (None for permanent)
            
        Returns:
            True if blocked, False if exempted
        """
        # Check if IP is exempted before blocking
        exemption_store = get_exemption_store()
        if not should_block_ip(True, exemption_store.is_exempted, ip):
            logger.info(f"IP {ip} is exempted, not blocking: {reason}")
            return False
        
        # Block the IP
        blocklist_store = get_blocklist_store()
        blocklist_store.block_ip(ip, reason, duration, extended_request_info=extended_request_info)
        
        return True
    
    @classmethod
    def unblock(cls, ip: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if successfully unblocked
        """
        blocklist_store = get_blocklist_store()
        return blocklist_store.unblock_ip(ip)
    
    @classmethod
    def is_blocked(cls, ip: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blocked
        """
        # Always check exemption first
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return False
        
        blocklist_store = get_blocklist_store()
        return blocklist_store.is_blocked(ip)
    
    @classmethod
    def get_block_info(cls, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a blocked IP.
        
        Args:
            ip: IP address to check
            
        Returns:
            Block information dictionary or None
        """
        blocklist_store = get_blocklist_store()
        return blocklist_store.get_block_info(ip)
    
    @classmethod
    def get_blocked_ips(cls) -> List[str]:
        """
        Get list of all currently blocked IP addresses.
        
        Returns:
            List of blocked IP addresses
        """
        blocklist_store = get_blocklist_store()
        return blocklist_store.get_blocked_ips()
    
    @classmethod
    def get_statistics(cls) -> Dict[str, Any]:
        """
        Get blocking statistics.
        
        Returns:
            Statistics dictionary
        """
        blocklist_store = get_blocklist_store()
        return blocklist_store.get_block_stats()
    
    @classmethod
    def cleanup_expired(cls) -> int:
        """
        Clean up expired blocks (for backends that don't auto-expire).
        
        Returns:
            Number of blocks cleaned up
        """
        # This is mainly handled by the storage backend's TTL mechanism,
        # but we can add manual cleanup here if needed
        blocklist_store = get_blocklist_store()
        blocked_ips = blocklist_store.get_blocked_ips()
        
        cleaned = 0
        current_time = time.time()
        
        for ip in blocked_ips:
            block_info = blocklist_store.get_block_info(ip)
            if block_info and not block_info.get('permanent', True):
                # Check if block has expired
                blocked_at = block_info.get('blocked_at', 0)
                duration = block_info.get('duration', 0)
                
                if duration and (current_time - blocked_at) > duration:
                    blocklist_store.unblock_ip(ip)
                    cleaned += 1
                    logger.info(f"Expired block removed for IP {ip}")
        
        return cleaned
    
    @classmethod
    def block_temporary(cls, ip: str, reason: str, minutes: int = 60) -> bool:
        """
        Block an IP for a temporary duration.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            minutes: Block duration in minutes
            
        Returns:
            True if blocked, False if exempted
        """
        duration = minutes * 60  # Convert to seconds
        return cls.block(ip, f"Temporary: {reason}", duration)
    
    @classmethod
    def block_permanent(cls, ip: str, reason: str) -> bool:
        """
        Permanently block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            
        Returns:
            True if blocked, False if exempted
        """
        return cls.block(ip, f"Permanent: {reason}", 0)
    
    @classmethod
    def add_to_allowlist(cls, ip: str, reason: str = "Manual allowlist"):
        """
        Add an IP to the allowlist (exemption list).
        
        Args:
            ip: IP address to allowlist
            reason: Reason for allowlisting
        """
        exemption_store = get_exemption_store()
        exemption_store.add_ip(ip, reason)
        
        # If IP was blocked, unblock it
        if cls.is_blocked(ip):
            cls.unblock(ip)
            logger.info(f"Unblocked {ip} due to allowlist addition")
    
    @classmethod
    def remove_from_allowlist(cls, ip: str):
        """
        Remove an IP from the allowlist.
        
        Args:
            ip: IP address to remove from allowlist
            
        Returns:
            True if removed
        """
        exemption_store = get_exemption_store()
        return exemption_store.remove_ip(ip)
    
    @classmethod
    def is_allowlisted(cls, ip: str) -> bool:
        """
        Check if an IP is allowlisted.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if allowlisted
        """
        exemption_store = get_exemption_store()
        return exemption_store.is_exempted(ip)
    
    @classmethod
    def get_allowlist(cls) -> Dict[str, Any]:
        """
        Get allowlist information.
        
        Returns:
            Dictionary with allowlisted IPs and patterns
        """
        exemption_store = get_exemption_store()
        return {
            'ips': list(exemption_store.get_exempted_ips()),
            'patterns': exemption_store.get_exempted_patterns()
        }
    
    @classmethod 
    def bulk_block(cls, ips: List[str], reason: str, duration: Optional[int] = None) -> Dict[str, bool]:
        """
        Block multiple IPs at once.
        
        Args:
            ips: List of IP addresses to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
            
        Returns:
            Dictionary mapping IP -> blocked status
        """
        results = {}
        
        for ip in ips:
            try:
                results[ip] = cls.block(ip, reason, duration)
            except Exception as e:
                logger.error(f"Failed to block IP {ip}: {e}")
                results[ip] = False
        
        return results
    
    @classmethod
    def bulk_unblock(cls, ips: List[str]) -> Dict[str, bool]:
        """
        Unblock multiple IPs at once.
        
        Args:
            ips: List of IP addresses to unblock
            
        Returns:
            Dictionary mapping IP -> unblock status  
        """
        results = {}
        
        for ip in ips:
            try:
                results[ip] = cls.unblock(ip)
            except Exception as e:
                logger.error(f"Failed to unblock IP {ip}: {e}")
                results[ip] = False
        
        return results
    
    @classmethod
    def get_recent_blocks(cls, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get recently blocked IPs.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent block entries
        """
        cutoff_time = time.time() - (hours * 3600)
        recent_blocks: List[Dict[str, Any]] = []
        seen = set()

        # Build from active blocked entries using the same manager APIs used by
        # callers/tests to avoid backend-instance drift.
        for ip in cls.get_blocked_ips():
            entry = cls.get_block_info(ip) or {}
            if not entry:
                continue
            entry_ip = entry.get("ip") or ip
            blocked_at = entry.get("blocked_at")
            if blocked_at is None:
                blocked_at = time.time()
                entry["blocked_at"] = blocked_at
            try:
                blocked_ts = float(blocked_at)
            except Exception:
                blocked_ts = 0.0
            if blocked_ts >= cutoff_time:
                key = (entry_ip, blocked_ts, entry.get("reason", ""))
                if key not in seen:
                    entry["ip"] = entry_ip
                    recent_blocks.append(entry)
                    seen.add(key)
        
        # Sort by most recent first
        recent_blocks.sort(key=lambda x: x.get('blocked_at', 0), reverse=True)
        
        return recent_blocks
    
    @classmethod
    def get_top_blocked_reasons(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most common blocking reasons.
        
        Args:
            limit: Maximum number of reasons to return
            
        Returns:
            List of reasons with counts
        """
        stats = cls.get_statistics()
        reason_counts = stats.get('reason_counts', {})
        
        # Sort by count descending
        sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'reason': reason, 'count': count}
            for reason, count in sorted_reasons[:limit]
        ]


# Compatibility aliases for callers using the previous terminology.
get_blacklist_store = get_blocklist_store
BlacklistManager = BlocklistManager
BlocklistManager.add_to_whitelist = BlocklistManager.__dict__['add_to_allowlist']
BlocklistManager.remove_from_whitelist = BlocklistManager.__dict__['remove_from_allowlist']
BlocklistManager.is_whitelisted = BlocklistManager.__dict__['is_allowlisted']
BlocklistManager.get_whitelist = BlocklistManager.__dict__['get_allowlist']
