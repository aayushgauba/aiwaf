import os
import sys
import subprocess
import re
from django.core.management.base import BaseCommand
from django.conf import settings
import pkg_resources
import requests
from packaging import version, specifiers


class Command(BaseCommand):
    help = 'Check project dependencies for updates'

    def add_arguments(self, parser):
        parser.add_argument(
            '--format',
            choices=['table', 'json'],
            default='table',
            help='Output format (default: table)'
        )
        parser.add_argument(
            '--check-security',
            action='store_true',
            help='Also check for known security vulnerabilities'
        )
        parser.add_argument(
            '--check-compatibility',
            action='store_true',
            default=True,
            help='Check for package compatibility issues (default: True)'
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('🔍 Checking project dependencies...\n'))
        
        try:
            dependencies = self.get_project_dependencies()
            if not dependencies:
                self.stdout.write(self.style.WARNING('No dependencies found to check.'))
                return

            results = []
            for dep_name, current_constraint in dependencies.items():
                result = self.check_package(dep_name, current_constraint)
                results.append(result)

            self.display_results(results, options['format'])
            
            if options['check_compatibility']:
                self.check_compatibility(results)
            
            if options['check_security']:
                self.check_security_vulnerabilities(dependencies)
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error checking dependencies: {e}'))

    def get_project_dependencies(self):
        """Get dependencies from pyproject.toml or requirements.txt"""
        dependencies = {}
        
        # Check pyproject.toml first
        pyproject_path = os.path.join(settings.BASE_DIR, 'pyproject.toml')
        if os.path.exists(pyproject_path):
            dependencies.update(self.parse_pyproject_toml(pyproject_path))
        
        # Check requirements.txt
        requirements_path = os.path.join(settings.BASE_DIR, 'requirements.txt')
        if os.path.exists(requirements_path):
            dependencies.update(self.parse_requirements_txt(requirements_path))
        
        return dependencies

    def parse_pyproject_toml(self, filepath):
        """Parse dependencies from pyproject.toml"""
        dependencies = {}
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Simple regex to extract dependencies
            import re
            deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if deps_match:
                deps_text = deps_match.group(1)
                for line in deps_text.split(','):
                    line = line.strip().strip('"\'')
                    if line and not line.startswith('#'):
                        if '>=' in line or '==' in line or '~=' in line or '<' in line:
                            name = re.split(r'[><=~!]', line)[0].strip()
                            dependencies[name] = line
                        else:
                            dependencies[line] = line
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Could not parse pyproject.toml: {e}'))
        
        return dependencies

    def parse_requirements_txt(self, filepath):
        """Parse dependencies from requirements.txt"""
        dependencies = {}
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '>=' in line or '==' in line or '~=' in line or '<' in line:
                            name = re.split(r'[><=~!]', line)[0].strip()
                            dependencies[name] = line
                        else:
                            dependencies[line] = line
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Could not parse requirements.txt: {e}'))
        
        return dependencies

    def check_package(self, package_name, constraint):
        """Check a single package for updates"""
        try:
            # Get currently installed version
            try:
                installed_version = pkg_resources.get_distribution(package_name).version
            except pkg_resources.DistributionNotFound:
                return {
                    'name': package_name,
                    'constraint': constraint,
                    'installed': 'Not installed',
                    'latest': 'Unknown',
                    'status': 'not_installed',
                    'update_available': False
                }

            # Get latest version from PyPI
            latest_version = self.get_latest_version(package_name)
            
            # Determine status
            status = 'up_to_date'
            update_available = False
            
            if latest_version and version.parse(installed_version) < version.parse(latest_version):
                status = 'outdated'
                update_available = True
            elif latest_version and version.parse(installed_version) > version.parse(latest_version):
                status = 'ahead'
            
            return {
                'name': package_name,
                'constraint': constraint,
                'installed': installed_version,
                'latest': latest_version or 'Unknown',
                'status': status,
                'update_available': update_available
            }
            
        except Exception as e:
            return {
                'name': package_name,
                'constraint': constraint,
                'installed': 'Error',
                'latest': 'Error',
                'status': 'error',
                'update_available': False,
                'error': str(e)
            }

    def get_latest_version(self, package_name):
        """Get latest version from PyPI"""
        try:
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data['info']['version']
        except Exception:
            pass
        return None

    def display_results(self, results, format_type):
        """Display results in specified format"""
        if format_type == 'json':
            import json
            self.stdout.write(json.dumps(results, indent=2))
            return

        # Table format
        up_to_date = [r for r in results if r['status'] == 'up_to_date']
        outdated = [r for r in results if r['status'] == 'outdated']
        not_installed = [r for r in results if r['status'] == 'not_installed']
        errors = [r for r in results if r['status'] == 'error']

        # Summary
        total = len(results)
        self.stdout.write(f"📊 Summary: {total} packages checked")
        self.stdout.write(f"   ✅ Up to date: {len(up_to_date)}")
        self.stdout.write(f"   ⚠️  Outdated: {len(outdated)}")
        self.stdout.write(f"   ❌ Not installed: {len(not_installed)}")
        self.stdout.write(f"   🔥 Errors: {len(errors)}\n")

        # Outdated packages
        if outdated:
            self.stdout.write(self.style.WARNING("⚠️  OUTDATED PACKAGES:"))
            self.stdout.write("─" * 80)
            for pkg in outdated:
                self.stdout.write(
                    f"📦 {pkg['name']:<20} {pkg['installed']:<12} → {pkg['latest']:<12} "
                    f"(constraint: {pkg['constraint']})"
                )
            self.stdout.write("")

        # Up to date packages
        if up_to_date:
            self.stdout.write(self.style.SUCCESS("✅ UP TO DATE PACKAGES:"))
            self.stdout.write("─" * 80)
            for pkg in up_to_date:
                self.stdout.write(
                    f"📦 {pkg['name']:<20} {pkg['installed']:<12} "
                    f"(constraint: {pkg['constraint']})"
                )
            self.stdout.write("")

        # Not installed packages
        if not_installed:
            self.stdout.write(self.style.ERROR("❌ NOT INSTALLED PACKAGES:"))
            self.stdout.write("─" * 80)
            for pkg in not_installed:
                self.stdout.write(f"📦 {pkg['name']:<20} (constraint: {pkg['constraint']})")
            self.stdout.write("")

        # Errors
        if errors:
            self.stdout.write(self.style.ERROR("🔥 PACKAGES WITH ERRORS:"))
            self.stdout.write("─" * 80)
            for pkg in errors:
                error_msg = pkg.get('error', 'Unknown error')
                self.stdout.write(f"📦 {pkg['name']:<20} Error: {error_msg}")
            self.stdout.write("")

        # Update command suggestions
        if outdated:
            self.stdout.write(self.style.HTTP_INFO("💡 To update outdated packages, run:"))
            update_cmd = "pip install --upgrade " + " ".join([pkg['name'] for pkg in outdated])
            self.stdout.write(f"   {update_cmd}")

    def check_compatibility(self, results):
        """Check for package compatibility issues"""
        self.stdout.write(self.style.HTTP_INFO("\n🔍 Checking package compatibility..."))
        
        # Known compatibility rules
        compatibility_rules = self.get_compatibility_rules()
        conflicts = []
        warnings = []
        
        # Check for version conflicts
        for pkg in results:
            if pkg['status'] in ['up_to_date', 'outdated', 'ahead']:
                pkg_name = pkg['name'].lower()
                installed_ver = pkg['installed']
                latest_ver = pkg['latest']
                
                # Check against compatibility rules
                for rule in compatibility_rules:
                    if rule['package'] == pkg_name:
                        conflict = self.check_package_rule(pkg, rule, results)
                        if conflict:
                            if conflict['severity'] == 'error':
                                conflicts.append(conflict)
                            else:
                                warnings.append(conflict)
        
        # Check for missing dependencies of packages
        missing_deps = self.check_missing_dependencies(results)
        conflicts.extend(missing_deps)
        
        # Display results
        if conflicts:
            self.stdout.write(self.style.ERROR("\n❌ COMPATIBILITY CONFLICTS:"))
            self.stdout.write("─" * 80)
            for conflict in conflicts:
                self.stdout.write(f"🚨 {conflict['message']}")
                if 'suggestion' in conflict:
                    self.stdout.write(f"   💡 {conflict['suggestion']}")
            self.stdout.write("")
        
        if warnings:
            self.stdout.write(self.style.WARNING("\n⚠️  COMPATIBILITY WARNINGS:"))
            self.stdout.write("─" * 80)
            for warning in warnings:
                self.stdout.write(f"⚠️  {warning['message']}")
                if 'suggestion' in warning:
                    self.stdout.write(f"   💡 {warning['suggestion']}")
            self.stdout.write("")
        
        if not conflicts and not warnings:
            self.stdout.write(self.style.SUCCESS("✅ All packages appear to be compatible!"))

    def get_compatibility_rules(self):
        """Define known compatibility rules between packages"""
        return [
            {
                'package': 'numpy',
                'conflicts_with': [
                    {
                        'package': 'pandas',
                        'numpy_versions': '>=2.0',
                        'pandas_versions': '<2.1',
                        'message': 'NumPy 2.0+ requires pandas 2.1+ for compatibility',
                        'severity': 'error'
                    }
                ]
            },
            {
                'package': 'scikit-learn',
                'conflicts_with': [
                    {
                        'package': 'numpy',
                        'sklearn_versions': '>=1.3',
                        'numpy_versions': '<1.19',
                        'message': 'scikit-learn 1.3+ requires NumPy 1.19+',
                        'severity': 'error'
                    },
                    {
                        'package': 'pandas',
                        'sklearn_versions': '>=1.2',
                        'pandas_versions': '<1.0',
                        'message': 'scikit-learn 1.2+ works best with pandas 1.0+',
                        'severity': 'warning'
                    }
                ]
            },
            {
                'package': 'pandas',
                'conflicts_with': [
                    {
                        'package': 'numpy',
                        'pandas_versions': '>=2.0',
                        'numpy_versions': '<1.22',
                        'message': 'pandas 2.0+ requires NumPy 1.22+',
                        'severity': 'error'
                    }
                ]
            },
            {
                'package': 'django',
                'conflicts_with': [
                    {
                        'package': 'pandas',
                        'django_versions': '>=4.0',
                        'pandas_versions': '<1.3',
                        'message': 'Django 4.0+ works better with pandas 1.3+',
                        'severity': 'warning'
                    }
                ]
            }
        ]

    def check_package_rule(self, pkg, rule, all_results):
        """Check a specific package against compatibility rules"""
        pkg_name = pkg['name'].lower()
        
        for conflict_rule in rule.get('conflicts_with', []):
            # Find the conflicting package in results
            conflicting_pkg = None
            for other_pkg in all_results:
                if other_pkg['name'].lower() == conflict_rule['package']:
                    conflicting_pkg = other_pkg
                    break
            
            if not conflicting_pkg or conflicting_pkg['status'] == 'not_installed':
                continue
            
            # Check version constraints
            pkg_version = pkg['installed']
            other_version = conflicting_pkg['installed']
            
            try:
                # Check if this package version matches the conflict rule
                pkg_constraint_key = f"{pkg_name}_versions"
                other_constraint_key = f"{conflict_rule['package']}_versions"
                
                pkg_constraint = conflict_rule.get(pkg_constraint_key)
                other_constraint = conflict_rule.get(other_constraint_key)
                
                pkg_matches = self.version_matches_constraint(pkg_version, pkg_constraint) if pkg_constraint else True
                other_matches = self.version_matches_constraint(other_version, other_constraint) if other_constraint else True
                
                if pkg_matches and other_matches:
                    suggestion = f"Consider updating {conflict_rule['package']} or {pkg_name}"
                    if conflict_rule['severity'] == 'error':
                        suggestion = f"REQUIRED: Update {conflict_rule['package']} or downgrade {pkg_name}"
                    
                    return {
                        'message': f"{pkg_name} {pkg_version} + {conflict_rule['package']} {other_version}: {conflict_rule['message']}",
                        'suggestion': suggestion,
                        'severity': conflict_rule['severity']
                    }
            except Exception:
                continue
        
        return None

    def version_matches_constraint(self, version_str, constraint_str):
        """Check if a version matches a constraint"""
        try:
            spec = specifiers.SpecifierSet(constraint_str)
            return version.parse(version_str) in spec
        except Exception:
            return False

    def check_missing_dependencies(self, results):
        """Check for missing dependencies that packages might need"""
        conflicts = []
        
        # Get installed packages
        installed_packages = {pkg['name'].lower(): pkg for pkg in results 
                            if pkg['status'] in ['up_to_date', 'outdated', 'ahead']}
        
        # Check key dependencies
        key_dependencies = {
            'pandas': ['numpy'],
            'scikit-learn': ['numpy', 'joblib'],
            'django': []  # Django has its own dependency management
        }
        
        for pkg_name, required_deps in key_dependencies.items():
            if pkg_name in installed_packages:
                for dep in required_deps:
                    if dep not in installed_packages:
                        conflicts.append({
                            'message': f"{pkg_name} requires {dep} but it's not installed",
                            'suggestion': f"Install {dep}: pip install {dep}",
                            'severity': 'error'
                        })
        
        return conflicts

    def check_security_vulnerabilities(self, dependencies):
        """Check for known security vulnerabilities using safety"""
        self.stdout.write(self.style.HTTP_INFO("\n🔒 Checking for security vulnerabilities..."))
        try:
            # Try to use safety if available
            result = subprocess.run(['safety', 'check', '--json'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                import json
                vulns = json.loads(result.stdout)
                if vulns:
                    self.stdout.write(self.style.ERROR(f"⚠️  Found {len(vulns)} security vulnerabilities!"))
                    for vuln in vulns[:5]:  # Show first 5
                        self.stdout.write(f"   📦 {vuln.get('package')}: {vuln.get('vulnerability')}")
                else:
                    self.stdout.write(self.style.SUCCESS("✅ No known security vulnerabilities found"))
            else:
                self.stdout.write(self.style.WARNING("Could not check vulnerabilities (safety not available)"))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.stdout.write(self.style.WARNING("Security check skipped (install 'safety' package for vulnerability scanning)"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Security check failed: {e}"))
