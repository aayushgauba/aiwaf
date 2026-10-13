"""
AIWAF Auto-Configuration Module

Automatically detects Flask app configuration and data directories
without requiring user intervention.
"""

import os
import sys
import importlib
import inspect
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class AIWAFAutoConfig:
    """Automatically detect and configure AIWAF data directory."""
    
    def __init__(self):
        self.detected_config = {}
        self.data_dir = None
        self.flask_app = None
        
    def auto_detect_data_directory(self) -> str:
        """
        Automatically detect the correct data directory through multiple methods.
        Uses deterministic approach to always return the same directory regardless of working directory.
        Returns the absolute path to the data directory.
        """
        # Method 1: Environment variable (highest priority - always consistent)
        if self._check_environment_variable():
            return self.data_dir

        # Older Flask installations use the project's aiwaf_data directory.
        # Prefer that application's policy over unrelated user/global stores.
        for project_dir in (Path.cwd() / 'aiwaf_data', Path.cwd() / '.aiwaf' / 'data'):
            if self._has_policy_files(project_dir):
                self.data_dir = str(project_dir.absolute())
                self.detected_config = {
                    'method': 'existing_project_directory',
                    'found_at': self.data_dir,
                }
                return self.data_dir
        if (Path.cwd() / 'aiwaf_data.csv').is_file():
            self.data_dir = str((Path.cwd() / 'aiwaf_data').absolute())
            self.detected_config = {'method': 'existing_project_directory', 'found_at': self.data_dir}
            return self.data_dir
            
        # Method 2: Find the BEST existing data directory (most data, avoid nesting)
        if self._find_best_existing_data_directory():
            return self.data_dir
            
        # Method 3: Create in user-specific location (consistent across sessions)
        return self._create_user_data_directory()
    
    def _check_environment_variable(self) -> bool:
        """Check if AIWAF_DATA_DIR is set in environment."""
        env_dir = os.environ.get('AIWAF_DATA_DIR')
        if env_dir:
            Path(env_dir).mkdir(parents=True, exist_ok=True)
            self.data_dir = str(Path(env_dir).absolute())
            self.detected_config['method'] = 'environment_variable'
            return True
        return False
    
    def _find_flask_app_config(self) -> bool:
        """Find Flask app and read its AIWAF configuration."""
        try:
            # Look for common Flask app patterns
            app_candidates = [
                'app',
                'application', 
                'main',
                'server',
                'wsgi'
            ]
            
            # Search in current directory and subdirectories
            current_dir = Path.cwd()
            python_files = list(current_dir.rglob("*.py"))
            
            for py_file in python_files:
                if self._analyze_python_file_for_flask_app(py_file):
                    return True
                    
        except Exception as e:
            logger.info(f" Flask app detection failed: {e}")
            
        return False
    
    def _analyze_python_file_for_flask_app(self, py_file: Path) -> bool:
        """Analyze a Python file to find Flask app configuration."""
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Look for Flask app creation and AIWAF configuration
            if 'Flask(' in content and 'AIWAF' in content:
                # Try to extract AIWAF_DATA_DIR configuration
                lines = content.split('\n')
                for line in lines:
                    if 'AIWAF_DATA_DIR' in line and '=' in line and not line.strip().startswith('#'):
                        # Extract the value (handle both quotes and variables)
                        try:
                            # Find the part after =
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                value_part = parts[1].strip()
                                
                                # Remove quotes and clean up
                                value = value_part.strip("'\"").strip()
                                
                                # Skip if it's a variable reference or environment lookup
                                if any(keyword in value for keyword in ['os.', 'environ', 'getenv', '{']):
                                    continue
                                
                                if value and value != 'aiwaf_data':  # Skip default values
                                    # Resolve relative to the file's directory
                                    if not Path(value).is_absolute():
                                        data_dir = py_file.parent / value
                                    else:
                                        data_dir = Path(value)
                                        
                                    if data_dir.exists() or self._can_create_directory(data_dir):
                                        self.data_dir = str(data_dir.absolute())
                                        self.detected_config['method'] = 'flask_app_config'
                                        self.detected_config['source_file'] = str(py_file)
                                        return True
                        except Exception:
                            continue
                        
        except Exception:
            pass
            
        return False
    
    def _search_existing_data_directories(self) -> bool:
        """Search for existing aiwaf_data directories."""
        search_paths = [
            Path.cwd(),  # Current directory
            Path.cwd().parent,  # Parent directory
            Path.home() / 'aiwaf_data',  # Home directory
        ]
        
        # Also search in common web app locations
        common_paths = [
            '/var/www',
            '/opt',
            '/home/ubuntu',
            '/app',  # Docker common path
        ]
        
        for path_str in common_paths:
            path = Path(path_str)
            if path.exists():
                search_paths.append(path)
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
                
            # Look for aiwaf_data directories - only direct children, not recursive
            try:
                # Check if there's a direct aiwaf_data subdirectory
                aiwaf_data_path = search_path / 'aiwaf_data'
                if aiwaf_data_path.exists() and aiwaf_data_path.is_dir() and self._validate_aiwaf_data_dir(aiwaf_data_path):
                    self.data_dir = str(aiwaf_data_path.absolute())
                    self.detected_config['method'] = 'existing_directory_search'
                    self.detected_config['found_at'] = str(aiwaf_data_path)
                    return True
            except (PermissionError, OSError):
                continue
                
        return False
    
    def _validate_aiwaf_data_dir(self, path: Path) -> bool:
        """Validate that a directory looks like an AIWAF data directory."""
        # Check for characteristic files
        csv_files = ['whitelist.csv', 'blacklist.csv', 'keywords.csv', 'geo_blocked_countries.csv', 'path_exemptions.csv']
        
        # If any CSV files exist, consider it valid
        if any((path / csv_file).exists() for csv_file in csv_files):
            return True
            
        # If directory is empty but writable, also consider valid
        try:
            if not any(path.iterdir()) and os.access(path, os.W_OK):
                return True
        except (PermissionError, OSError):
            pass
            
        return False

    @staticmethod
    def _has_policy_files(path: Path) -> bool:
        from aiwaf.core.storage_schema import CSV_HEADERS

        return path.is_dir() and any((path / name).is_file() for name in (*CSV_HEADERS, 'runtime_store.csv'))
    
    def _detect_project_structure(self) -> bool:
        """Detect project structure and infer best data directory location."""
        current_dir = Path.cwd()
        
        # Look for project indicators
        project_indicators = [
            'setup.py',
            'pyproject.toml', 
            'requirements.txt',
            'Pipfile',
            'poetry.lock',
            'manage.py',  # Django
            'app.py',     # Flask
            'main.py',    # Generic
        ]
        
        # Find project root
        project_root = None
        for parent in [current_dir] + list(current_dir.parents)[:5]:
            if any((parent / indicator).exists() for indicator in project_indicators):
                project_root = parent
                break
        
        if project_root:
            # Create data directory in project root
            data_dir = project_root / 'aiwaf_data'
            if self._can_create_directory(data_dir):
                data_dir.mkdir(exist_ok=True)
                self.data_dir = str(data_dir.absolute())
                self.detected_config['method'] = 'project_structure_detection'
                self.detected_config['project_root'] = str(project_root)
                return True
                
        return False
    
    def _create_fallback_directory(self) -> str:
        """Create fallback directory in the most appropriate location."""
        fallback_locations = [
            Path.cwd() / 'aiwaf_data',  # Current directory
            Path.home() / '.aiwaf' / 'data',  # User home
            Path('/tmp/aiwaf_data') if os.name != 'nt' else Path.cwd() / 'aiwaf_data',  # Temp (Unix only)
        ]
        
        for location in fallback_locations:
            if self._can_create_directory(location):
                location.mkdir(parents=True, exist_ok=True)
                self.data_dir = str(location.absolute())
                self.detected_config['method'] = 'fallback_creation'
                self.detected_config['location'] = str(location)
                return self.data_dir
        
        # Last resort
        self.data_dir = 'aiwaf_data'
        self.detected_config['method'] = 'last_resort'
        return self.data_dir
    
    def _can_create_directory(self, path: Path) -> bool:
        """Check if we can create a directory at the given path."""
        try:
            if path.exists():
                return os.access(path, os.W_OK)
            else:
                # Check parent directory permissions
                parent = path.parent
                return parent.exists() and os.access(parent, os.W_OK)
        except (PermissionError, OSError):
            return False
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get information about how the configuration was detected."""
        return {
            'data_directory': self.data_dir,
            'detection_method': self.detected_config.get('method', 'unknown'),
            'details': self.detected_config
        }
    
    def auto_detect_log_directory(self) -> str:
        """
        Automatically detect the correct log directory.
        Uses similar deterministic approach as data directory.
        """
        # Initialize log detection state
        self.log_dir = None
        self.log_config = {}
        
        # Method 1: Environment variable
        env_log_dir = os.environ.get('AIWAF_LOG_DIR')
        if env_log_dir and Path(env_log_dir).exists():
            self.log_dir = str(Path(env_log_dir).absolute())
            self.log_config['method'] = 'environment_variable'
            return self.log_dir
            
        # Method 2: Find existing log directories with actual log files
        log_candidates = []
        
        # Search in predictable locations (prefer 'logs' over 'aiwaf_logs')
        search_locations = [
            Path.home() / '.aiwaf' / 'logs',
            Path.home() / 'logs',
            Path.home() / 'aiwaf_logs',  # legacy support
        ]
        
        # Add locations relative to the data directory
        if self.data_dir:
            data_path = Path(self.data_dir)
            search_locations.extend([
                data_path.parent / 'logs',
                data_path / 'logs',
                data_path.parent / 'aiwaf_logs',  # legacy support
            ])
        
        # Add locations relative to package
        try:
            import aiwaf.flask as aiwaf_flask
            package_path = Path(aiwaf_flask.__file__).parent.parent
            search_locations.extend([
                package_path.parent / 'logs',
                package_path / 'logs',
                package_path.parent / 'aiwaf_logs',  # legacy support
                package_path / 'aiwaf_logs',  # legacy support
            ])
        except Exception:
            pass
        
        # Evaluate log directories
        for location in search_locations:
            if location.exists() and self._validate_log_directory(location):
                log_score = self._calculate_log_directory_score(location)
                log_candidates.append((log_score, str(location.absolute()), location))
        
        if log_candidates:
            # Choose the directory with the most log files
            log_candidates.sort(reverse=True)
            best_score, best_path, best_location = log_candidates[0]
            
            self.log_dir = best_path
            self.log_config['method'] = 'existing_log_directory'
            self.log_config['found_at'] = best_path
            self.log_config['log_score'] = best_score
            return self.log_dir
        
        # Method 3: Create log directory in consistent location (prefer 'logs')
        log_locations = [
            Path.home() / '.aiwaf' / 'logs',
            Path.home() / 'logs',
            Path.home() / 'aiwaf_logs',  # legacy fallback
        ]
        
        # Prefer location near data directory if available
        if self.data_dir:
            data_path = Path(self.data_dir)
            log_locations.insert(0, data_path.parent / 'logs')
        
        for location in log_locations:
            if self._can_create_directory(location):
                location.mkdir(parents=True, exist_ok=True)
                self.log_dir = str(location.absolute())
                self.log_config['method'] = 'created_log_directory'
                self.log_config['location'] = str(location)
                return self.log_dir
        
        # Fallback to standard 'logs' directory
        fallback_log_dir = 'logs'
        self.log_dir = str(Path(fallback_log_dir).absolute())
        self.log_config['method'] = 'fallback_relative'
        return self.log_dir
    
    def _validate_log_directory(self, path: Path) -> bool:
        """Validate that a directory looks like a log directory."""
        # Check for log files
        log_patterns = ['*.log', '*.txt', 'access.log*', 'aiwaf.log*']
        
        for pattern in log_patterns:
            if list(path.glob(pattern)):
                return True
        
        # If directory exists and is writable, consider it valid for log creation
        try:
            return path.is_dir() and os.access(path, os.W_OK)
        except (PermissionError, OSError):
            return False
    
    def _calculate_log_directory_score(self, path: Path) -> int:
        """Calculate a score for a log directory based on its contents."""
        score = 0
        
        # Bonus for preferred directory names (prefer 'logs' over 'aiwaf_logs')
        dir_name = path.name.lower()
        if dir_name == 'logs':
            score += 50  # Strong preference for standard 'logs' directory
        elif 'logs' in dir_name:
            score += 20  # Moderate preference for directories containing 'logs'
        
        # Count log files
        log_patterns = ['*.log', '*.txt']
        for pattern in log_patterns:
            log_files = list(path.glob(pattern))
            score += len(log_files) * 10
            
            # Add score based on file sizes
            for log_file in log_files:
                try:
                    size = log_file.stat().st_size
                    score += min(size // 1024, 100)  # Cap size contribution
                except (PermissionError, OSError):
                    pass
        
        return score
    
    def get_log_config_info(self) -> Dict[str, Any]:
        """Get information about how the log directory was detected."""
        return {
            'log_directory': getattr(self, 'log_dir', None),
            'detection_method': getattr(self, 'log_config', {}).get('method', 'unknown'),
            'details': getattr(self, 'log_config', {})
        }
    
    def _use_package_based_data_directory(self) -> bool:
        """Use data directory relative to the installed package location."""
        try:
            import aiwaf.flask as aiwaf_flask
            package_path = Path(aiwaf_flask.__file__).parent.parent  # Go up to site-packages level
            
            # Look for data directory near the package installation
            # Only check direct locations, not nested to avoid aiwaf_data/aiwaf_data
            potential_locations = [
                package_path.parent / 'aiwaf_data',  # One level up from site-packages
                package_path / 'aiwaf_data',         # Next to site-packages
            ]
            
            for location in potential_locations:
                if location.exists() and self._validate_aiwaf_data_dir(location):
                    self.data_dir = str(location.absolute())
                    self.detected_config['method'] = 'package_based_location'
                    self.detected_config['package_path'] = str(package_path)
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def _find_best_existing_data_directory(self) -> bool:
        """Find the existing data directory with the most data (most reliable)."""
        candidates = []
        
        # Search in FIXED, deterministic locations only (no working directory dependence)
        search_paths = [
            Path.home() / '.aiwaf' / 'data',  # User-specific (highest priority)
            Path.home() / 'aiwaf_data',       # User home
        ]
        
        # On Windows, add AppData location
        if os.name == 'nt':
            appdata = os.environ.get('APPDATA')
            if appdata:
                search_paths.insert(0, Path(appdata) / 'aiwaf' / 'data')
        
        # Add common system locations (fixed paths)
        if os.name != 'nt':
            search_paths.append(Path('/var/lib/aiwaf'))
        else:
            search_paths.append(Path('C:/ProgramData/aiwaf'))
        
        # Add package-related locations (deterministic based on package location)
        try:
            import aiwaf.flask as aiwaf_flask
            package_path = Path(aiwaf_flask.__file__).parent.parent
            search_paths.extend([
                package_path.parent / 'aiwaf_data',  # One level up from package
                package_path / 'aiwaf_data',         # Next to package
            ])
        except Exception:
            pass
        
        # Evaluate each candidate - only look at direct children, not nested
        for search_path in search_paths:
            if not search_path.exists():
                continue
                
            try:
                # Each candidate is already a data directory, including those
                # named 'data'. Do not accidentally search data/aiwaf_data.
                if self._has_policy_files(search_path):
                    data_score = self._calculate_data_directory_score(search_path)
                    candidates.append((data_score, str(search_path.absolute()), search_path))
                    
            except (PermissionError, OSError):
                continue
        
        # Choose the candidate with the highest data score
        if candidates:
            candidates.sort(reverse=True)  # Sort by score (descending)
            best_score, best_path, best_item = candidates[0]
            
            self.data_dir = best_path
            self.detected_config['method'] = 'best_existing_directory'
            self.detected_config['found_at'] = best_path
            self.detected_config['data_score'] = best_score
            self.detected_config['total_candidates'] = len(candidates)
            return True
                
        return False
    
    def _calculate_data_directory_score(self, path: Path) -> int:
        """Calculate a score for a data directory based on its contents."""
        score = 0
        csv_files = ['whitelist.csv', 'blacklist.csv', 'keywords.csv', 'geo_blocked_countries.csv', 'path_exemptions.csv']
        
        for csv_file in csv_files:
            csv_path = path / csv_file
            if csv_path.exists():
                try:
                    # Score based on file size and line count
                    file_size = csv_path.stat().st_size
                    score += min(file_size, 1000)  # Cap size contribution
                    
                    # Count lines (more data = higher score)
                    with open(csv_path, 'r') as f:
                        line_count = sum(1 for _ in f)
                        score += line_count * 10  # Lines are worth more than just file size
                        
                except (PermissionError, OSError):
                    pass
        
        # Bonus for having all three files
        existing_files = sum(1 for csv_file in csv_files if (path / csv_file).exists())
        score += existing_files * 100
        
        return score
    
    def _create_user_data_directory(self) -> str:
        """Create data directory in user-specific location for consistency."""
        # User-specific data directory (always consistent regardless of working directory)
        user_data_locations = [
            Path.home() / '.aiwaf' / 'data',     # Unix-style hidden directory
            Path.home() / 'aiwaf_data',          # Simple user directory
        ]
        
        # On Windows, also try AppData
        if os.name == 'nt':
            appdata = os.environ.get('APPDATA')
            if appdata:
                user_data_locations.insert(0, Path(appdata) / 'aiwaf' / 'data')
        
        for location in user_data_locations:
            if self._can_create_directory(location):
                location.mkdir(parents=True, exist_ok=True)
                self.data_dir = str(location.absolute())
                self.detected_config['method'] = 'user_data_directory'
                self.detected_config['location'] = str(location)
                return self.data_dir
        
        # Absolute last resort - use a generic temp directory without reading OS identity
        import tempfile
        temp_dir = Path(tempfile.gettempdir()) / 'aiwaf_data'
        temp_dir.mkdir(exist_ok=True)
        self.data_dir = str(temp_dir.absolute())
        self.detected_config['method'] = 'temp_user_directory'
        self.detected_config['location'] = str(temp_dir)
        return self.data_dir


# Global instance for automatic configuration
_auto_config = None

def get_auto_configured_log_dir() -> Tuple[str, Dict[str, Any]]:
    """
    Get automatically configured log directory.
    Returns (log_dir_path, config_info)
    """
    global _auto_config
    if _auto_config is None:
        _auto_config = AIWAFAutoConfig()
    
    log_dir = _auto_config.auto_detect_log_directory()
    config_info = _auto_config.get_log_config_info()
    
    return log_dir, config_info


def get_auto_configured_data_dir() -> Tuple[str, Dict[str, Any]]:
    """
    Get automatically configured data directory.
    Returns (data_dir_path, config_info)
    """
    global _auto_config
    if _auto_config is None:
        _auto_config = AIWAFAutoConfig()
    
    data_dir = _auto_config.auto_detect_data_directory()
    config_info = _auto_config.get_config_info()
    
    return data_dir, config_info


def print_auto_config_info(config_info: Dict[str, Any]) -> None:
    """Print user-friendly information about auto-configuration."""
    method = config_info.get('detection_method', 'unknown')
    data_dir = config_info.get('data_directory', 'unknown')
    
    method_descriptions = {
        'environment_variable': 'Found AIWAF_DATA_DIR environment variable',
        'package_based_location': 'Located data directory near package installation',
        'best_existing_directory': 'Selected data directory with most existing data',
        'existing_project_directory': 'Found existing project CSV data',
        'user_data_directory': 'Created in user-specific location for consistency',
        'temp_user_directory': 'Using temporary user-specific directory',
        # Legacy methods (still supported)
        'flask_app_config': 'Detected from Flask app configuration',
        'existing_directory_search': 'Found existing aiwaf_data directory',
        'project_structure_detection': 'Detected from project structure',
        'fallback_creation': 'Created in fallback location',
        'last_resort': 'Using default relative path'
    }
    
    description = method_descriptions.get(method, 'Unknown detection method')
    logger.info(f" Auto-configured data directory: {data_dir}")
    logger.info(f" Detection method: {description}")
    
    # Additional details based on method
    details = config_info.get('details', {})
    if method == 'flask_app_config' and 'source_file' in details:
        logger.info(f" Source: {details['source_file']}")
    elif method == 'project_structure_detection' and 'project_root' in details:
        logger.info(f" Project root: {details['project_root']}")
    elif method == 'existing_directory_search' and 'found_at' in details:
        logger.info(f" Found at: {details['found_at']}")
    elif method == 'best_existing_directory':
        logger.info(f" Selected from {details.get('total_candidates', 0)} candidates")
        logger.info(f" Data score: {details.get('data_score', 0)}")
    elif method == 'package_based_location' and 'package_path' in details:
        logger.info(f" Package location: {details['package_path']}")
    elif method in ['user_data_directory', 'temp_user_directory'] and 'location' in details:
        logger.info(f" Created at: {details['location']}")
        logger.info(f" This location is consistent regardless of working directory")
