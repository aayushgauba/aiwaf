"""
Configuration management for AIWAF
"""
import os
import json
from typing import Dict, Any, Optional, List, Set
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AIWAFConfig:
    """
    Configuration management for AIWAF middleware settings.
    
    Supports loading configuration from:
    - Environment variables
    - JSON configuration files
    - Direct parameter setting
    """
    
    def __init__(
        self,
        config_file: Optional[str] = None,
        load_from_env: bool = True
    ):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to JSON configuration file
            load_from_env: Whether to load settings from environment variables
        """
        # Default configuration
        self._config = self._get_default_config()
        
        # Load from file if provided
        if config_file:
            self.load_from_file(config_file)
        
        # Load from environment if enabled
        if load_from_env:
            self.load_from_environment()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            # Storage settings
            'storage': {
                'backend': 'memory',  # 'memory', 'file', 'csv', or 'db'
                'file_path': 'aiwaf_data.json'
            },
            
            # Header validation middleware
            'header_validation': {
                'enabled': True,
                'block_suspicious': True,
                'quality_threshold': 3,
                'exempt_paths': [
                    '/health', '/healthz', '/status', '/ping', '/metrics',
                    '/favicon.ico', '/robots.txt'
                ],
                'custom_suspicious_patterns': [],
                'custom_legitimate_patterns': [],
                'trust_legitimate_bots': False
            },
            
            # Rate limiting
            'rate_limiting': {
                'enabled': True,
                'max_requests': 20,
                'window_seconds': 10,
                'flood_threshold': 40,
                'key_mode': 'ip_path',
                'soft_block_blocklist': False,
                # Cache backend for shared rate-limit buckets (FastAPI/Flask adapters).
                # - memory: per-process (default)
                # - redis: shared across workers (requires redis URL)
                'cache_backend': 'memory',
                'redis_url': None,
                'cache_key_prefix': 'aiwaf:rate:',
                'exempt_ips': [],
            },
            'ip_keyword_block': {
                'enabled': True,
                'sql_injection_mode': 'block',
                'payload_max_bytes': 65536,
                'malicious_keywords': [
                    '.php', 'xmlrpc', 'wp-', '.env', '.git', '.bak', 'shell', 'filemanager'
                ],
            },
            'honeypot': {
                'enabled': True,
                'min_form_time': 1.0,
                'max_page_time': 240,
            },
            'geo_block': {
                'enabled': False,
                'allow_countries': [],
                'block_countries': [],
            },
            'ai_anomaly': {
                'enabled': True,
            },
            'uuid_tamper': {
                'enabled': True,
            },
            'logging_middleware': {
                'enabled': True,
                'log_dir': 'aiwaf_logs',
                'log_format': 'combined',
            },
            
            # Blocklist management
            'blocklist': {
                'default_block_duration': 3600,  # 1 hour in seconds
                'permanent_block_threshold': 5,   # Number of violations for permanent block
                'auto_unblock_enabled': True,
                'cleanup_interval': 3600         # Cleanup expired blocks every hour
            },
            
            # Allowlist/exemption settings
            'exemptions': {
                'private_ips_exempted': True,
                'localhost_exempted': True,
                'auto_exempt_patterns': [
                    '127.0.0.1',
                    '::1',
                    '192.168.*.*',
                    '10.*.*.*',
                    '172.16.*.*'
                ]
            },
            
            # Security settings
            'security': {
                'log_blocked_requests': True,
                'log_suspicious_requests': True,
                'max_header_length': 8192,
                'max_user_agent_length': 512
            },
            
            # Performance settings
            'performance': {
                'enable_caching': True,
                'cache_duration': 300,
                'max_cache_entries': 10000
            },
            
            # Logging settings
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'log_file': None  # None for console only
            },
            'path_rules': [],
        }
    
    def load_from_file(self, config_file: str):
        """
        Load configuration from JSON file.
        
        Args:
            config_file: Path to JSON configuration file
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.warning(f"Configuration file not found: {config_file}")
            return
        
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            
            # Deep merge with existing config
            self._deep_merge(self._config, file_config)
            logger.info(f"Configuration loaded from {config_file}")
            
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load configuration from {config_file}: {e}")
    
    def load_from_environment(self):
        """Load configuration from environment variables."""
        env_mappings = {
            # Storage
            'AIWAF_STORAGE_BACKEND': ('storage', 'backend'),
            'AIWAF_STORAGE_FILE_PATH': ('storage', 'file_path'),
            'AIWAF_DATA_DIR': ('storage', 'data_dir'),
            
            # Header validation
            'AIWAF_HEADER_VALIDATION_ENABLED': ('header_validation', 'enabled', bool),
            'AIWAF_HEADER_BLOCK_SUSPICIOUS': ('header_validation', 'block_suspicious', bool),
            'AIWAF_HEADER_QUALITY_THRESHOLD': ('header_validation', 'quality_threshold', int),
            'AIWAF_HEADER_EXEMPT_PATHS': ('header_validation', 'exempt_paths', list),
            
            # Rate limiting
            'AIWAF_RATE_LIMITING_ENABLED': ('rate_limiting', 'enabled', bool),
            'AIWAF_RATE_MAX_REQUESTS': ('rate_limiting', 'max_requests', int),
            'AIWAF_RATE_WINDOW_SECONDS': ('rate_limiting', 'window_seconds', int),
            'AIWAF_RATE_KEY_MODE': ('rate_limiting', 'key_mode', str),
            'AIWAF_RATE_SOFT_BLOCK_BLOCKLIST': ('rate_limiting', 'soft_block_blocklist', bool),
            'AIWAF_RATE_CACHE_BACKEND': ('rate_limiting', 'cache_backend', str),
            'AIWAF_RATE_CACHE_KEY_PREFIX': ('rate_limiting', 'cache_key_prefix', str),
            'AIWAF_REDIS_URL': ('rate_limiting', 'redis_url', str),
            
            # Blocklist
            'AIWAF_BLOCKLIST_DEFAULT_DURATION': ('blocklist', 'default_block_duration', int),
            'AIWAF_BLOCKLIST_PERMANENT_THRESHOLD': ('blocklist', 'permanent_block_threshold', int),
            'AIWAF_BLOCKLIST_AUTO_UNBLOCK': ('blocklist', 'auto_unblock_enabled', bool),
            
            # Security
            'AIWAF_SQL_INJECTION_MODE': ('ip_keyword_block', 'sql_injection_mode', str),
            'AIWAF_PAYLOAD_MAX_BYTES': ('ip_keyword_block', 'payload_max_bytes', int),
            'AIWAF_LOG_BLOCKED': ('security', 'log_blocked_requests', bool),
            'AIWAF_LOG_SUSPICIOUS': ('security', 'log_suspicious_requests', bool),
            'AIWAF_MAX_HEADER_LENGTH': ('security', 'max_header_length', int),
            
            # Logging
            'AIWAF_LOG_LEVEL': ('logging', 'level'),
            'AIWAF_LOG_FILE': ('logging', 'log_file'),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is None:
                value = os.getenv(env_var.replace('BLOCKLIST', 'BLACKLIST').replace('ALLOWLIST', 'WHITELIST'))
            if value is not None:
                # Parse value based on type
                parsed_value = self._parse_env_value(value, config_path)
                self._set_nested_value(self._config, config_path[:2], parsed_value)
    
    def _parse_env_value(self, value: str, config_path: tuple):
        """Parse environment variable value to appropriate type."""
        if len(config_path) > 2:
            value_type = config_path[2]
        else:
            return value
        
        try:
            if value_type == bool:
                return value.lower() in ('true', '1', 'yes', 'on')
            elif value_type == int:
                return int(value)
            elif value_type == list:
                # Comma-separated values
                return [item.strip() for item in value.split(',') if item.strip()]
            else:
                return value
        except (ValueError, TypeError):
            logger.warning(f"Failed to parse environment value '{value}' as {value_type}")
            return value
    
    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set a nested configuration value."""
        if len(path) == 1:
            config[path[0]] = value
        else:
            if path[0] not in config:
                config[path[0]] = {}
            self._set_nested_value(config[path[0]], path[1:], value)
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Deep merge two dictionaries."""
        for key, value in update.items():
            original_key = key
            key = key.replace('blacklist', 'blocklist').replace('whitelist', 'allowlist')
            if key != original_key and key in update:
                continue
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation (e.g., 'header_validation.enabled')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.replace('blacklist', 'blocklist').replace('whitelist', 'allowlist').split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.replace('blacklist', 'blocklist').replace('whitelist', 'allowlist').split('.')
        config = self._config
        
        # Navigate to the parent dict
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the final value
        config[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]):
        """
        Update multiple configuration values.
        
        Args:
            updates: Dictionary of updates to apply
        """
        self._deep_merge(self._config, updates)
    
    def save_to_file(self, config_file: str):
        """
        Save current configuration to JSON file.
        
        Args:
            config_file: Path to save configuration
        """
        config_path = Path(config_file)
        
        try:
            # Create directory if needed
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(self._config, f, indent=2, default=str)
            
            logger.info(f"Configuration saved to {config_file}")
            
        except IOError as e:
            logger.error(f"Failed to save configuration to {config_file}: {e}")
    
    def get_all(self) -> Dict[str, Any]:
        """Get the complete configuration dictionary."""
        return self._config.copy()
    
    def reset_to_defaults(self):
        """Reset configuration to default values."""
        self._config = self._get_default_config()
        logger.info("Configuration reset to defaults")
    
    def validate(self) -> List[str]:
        """
        Validate the current configuration.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Validate storage backend
        storage_backend = self.get('storage.backend')
        if storage_backend not in ['memory', 'file', 'csv', 'db']:
            errors.append(f"Invalid storage backend: {storage_backend}")
        
        # Validate numeric values
        numeric_validations = [
            ('header_validation.quality_threshold', 0, 20),
            ('rate_limiting.max_requests', 1, 10000),
            ('rate_limiting.window_seconds', 1, 86400),
            ('blocklist.default_block_duration', 60, 86400 * 7),
            ('blocklist.permanent_block_threshold', 1, 100),
            ('security.max_header_length', 1024, 65536)
        ]
        
        for key, min_val, max_val in numeric_validations:
            value = self.get(key)
            if not isinstance(value, int) or value < min_val or value > max_val:
                errors.append(f"Invalid {key}: must be integer between {min_val} and {max_val}")
        
        # Validate log level
        log_level = self.get('logging.level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level not in valid_levels:
            errors.append(f"Invalid log level: {log_level}. Must be one of {valid_levels}")
        
        return errors
    
    def setup_logging(self):
        """Setup logging based on configuration."""
        log_level = self.get('logging.level', 'INFO')
        log_format = self.get('logging.format')
        log_file = self.get('logging.log_file')
        
        # Configure logging
        logging_config = {
            'level': getattr(logging, log_level),
            'format': log_format
        }
        
        if log_file:
            logging_config['filename'] = log_file
        
        logging.basicConfig(**logging_config)
        logger.info(f"Logging configured: level={log_level}, file={log_file}")
    
    def get_header_validation_config(self) -> Dict[str, Any]:
        """Get header validation specific configuration."""
        return self.get('header_validation', {})
    
    def get_storage_config(self) -> Dict[str, Any]:
        """Get storage specific configuration."""
        result = dict(self.get('storage', {}))
        if result.get('backend') == 'csv' and result.get('file_path') == 'aiwaf_data.json':
            # The default JSON path belongs to the file backend.
            result.pop('file_path')
        return result
    
    def get_rate_limiting_config(self) -> Dict[str, Any]:
        """Get rate limiting specific configuration."""
        return self.get('rate_limiting', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security specific configuration."""
        return self.get('security', {})
    
    def is_enabled(self, feature: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature: Feature name (e.g., 'header_validation', 'rate_limiting')
            
        Returns:
            True if feature is enabled
        """
        return self.get(f'{feature}.enabled', False)
    
    def enable_feature(self, feature: str):
        """Enable a feature."""
        self.set(f'{feature}.enabled', True)
        logger.info(f"Feature enabled: {feature}")
    
    def disable_feature(self, feature: str):
        """Disable a feature."""
        self.set(f'{feature}.enabled', False)
        logger.info(f"Feature disabled: {feature}")


# Global configuration instance
_config: Optional[AIWAFConfig] = None


def get_config() -> AIWAFConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = AIWAFConfig()
    return _config


def initialize_config(config_file: Optional[str] = None, **kwargs) -> AIWAFConfig:
    """
    Initialize the global configuration.
    
    Args:
        config_file: Path to configuration file
        **kwargs: Additional configuration parameters
        
    Returns:
        Configuration instance
    """
    global _config
    _config = AIWAFConfig(config_file=config_file)
    
    # Apply any additional configuration
    if kwargs:
        _config.update(kwargs)
    
    # Setup logging
    _config.setup_logging()
    
    # Validate configuration
    errors = _config.validate()
    if errors:
        for error in errors:
            logger.error(f"Configuration error: {error}")
        raise ValueError(f"Configuration validation failed: {errors}")
    
    logger.info("AIWAF configuration initialized successfully")
    return _config
