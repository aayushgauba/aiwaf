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
        parser.add_argument(
            '--upgrade',
            action='store_true',
            help='Automatically upgrade packages while maintaining stability'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be upgraded without actually upgrading'
        )
        parser.add_argument(
            '--update-requirements',
            action='store_true',
            help='Update requirements.txt with upgraded package versions'
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
            
            if options['upgrade']:
                upgraded_packages = self.perform_safe_upgrade(results, options['dry_run'])
                
                if options['update_requirements'] and upgraded_packages and not options['dry_run']:
                    self.update_requirements_file(upgraded_packages)
            
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

    def perform_safe_upgrade(self, results, dry_run=False):
        """Perform safe package upgrades while maintaining AIWAF compatibility"""
        self.stdout.write(self.style.HTTP_INFO("\n🔄 Planning safe package upgrades..."))
        
        # AIWAF compatibility constraints
        aiwaf_constraints = self.get_aiwaf_compatibility_constraints()
        
        # Get packages that can be safely upgraded
        safe_upgrades = []
        blocked_upgrades = []
        upgraded_packages = []  # Track successfully upgraded packages
        
        for pkg in results:
            if pkg['status'] == 'outdated' and pkg['name'].lower() != 'aiwaf':
                upgrade_plan = self.plan_safe_upgrade(pkg, aiwaf_constraints, results)
                if upgrade_plan['safe']:
                    safe_upgrades.append(upgrade_plan)
                else:
                    blocked_upgrades.append(upgrade_plan)
        
        # Display upgrade plan
        if safe_upgrades:
            self.stdout.write(self.style.SUCCESS("\n✅ SAFE UPGRADES PLANNED:"))
            self.stdout.write("─" * 80)
            for upgrade in safe_upgrades:
                pkg = upgrade['package']
                target_version = upgrade['target_version']
                self.stdout.write(
                    f"📦 {pkg['name']:<20} {pkg['installed']:<12} → {target_version:<12} "
                    f"(Latest: {pkg['latest']})"
                )
                if upgrade['reason']:
                    self.stdout.write(f"   💡 {upgrade['reason']}")
        
        if blocked_upgrades:
            self.stdout.write(self.style.WARNING("\n⚠️  UPGRADES BLOCKED FOR STABILITY:"))
            self.stdout.write("─" * 80)
            for upgrade in blocked_upgrades:
                pkg = upgrade['package']
                self.stdout.write(
                    f"❌ {pkg['name']:<20} {pkg['installed']:<12} ✗ {pkg['latest']:<12}"
                )
                self.stdout.write(f"   🚨 {upgrade['reason']}")
        
        if not safe_upgrades:
            self.stdout.write(self.style.NOTICE("ℹ️  No safe upgrades available at this time."))
            return []
        
        # Execute upgrades
        if dry_run:
            self.stdout.write(self.style.NOTICE("\n🏃 DRY RUN MODE - No packages will be upgraded"))
            upgrade_cmd = "pip install --upgrade " + " ".join([
                f"{u['package']['name']}=={u['target_version']}" if u['target_version'] != u['package']['latest'] 
                else u['package']['name'] 
                for u in safe_upgrades
            ])
            self.stdout.write(f"Commands that would be executed:")
            self.stdout.write(f"   {upgrade_cmd}")
            self.stdout.write(f"   pip cache purge  # Clear pip cache after upgrades")
            return []
            return []
        else:
            self.stdout.write(self.style.HTTP_INFO("\n🚀 Executing safe upgrades..."))
            success_count = 0
            
            for upgrade in safe_upgrades:
                pkg_name = upgrade['package']['name']
                target_version = upgrade['target_version']
                
                try:
                    if target_version == upgrade['package']['latest']:
                        cmd = ['pip', 'install', '--upgrade', pkg_name]
                    else:
                        cmd = ['pip', 'install', f"{pkg_name}=={target_version}"]
                    
                    self.stdout.write(f"   Upgrading {pkg_name}...")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0:
                        self.stdout.write(self.style.SUCCESS(f"   ✅ {pkg_name} upgraded successfully"))
                        success_count += 1
                        upgraded_packages.append({
                            'name': pkg_name,
                            'old_version': upgrade['package']['installed'],
                            'new_version': target_version
                        })
                    else:
                        self.stdout.write(self.style.ERROR(f"   ❌ Failed to upgrade {pkg_name}: {result.stderr}"))
                
                except subprocess.TimeoutExpired:
                    self.stdout.write(self.style.ERROR(f"   ❌ Timeout upgrading {pkg_name}"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"   ❌ Error upgrading {pkg_name}: {e}"))
            
            self.stdout.write(f"\n🎉 Upgrade complete: {success_count}/{len(safe_upgrades)} packages upgraded successfully")
            
            if success_count > 0:
                # Clear pip cache after successful upgrades
                self.stdout.write(self.style.HTTP_INFO("\n🧹 Clearing pip cache..."))
                try:
                    cache_result = subprocess.run(['pip', 'cache', 'purge'], 
                                                capture_output=True, text=True, timeout=60)
                    if cache_result.returncode == 0:
                        self.stdout.write(self.style.SUCCESS("   ✅ Pip cache cleared successfully"))
                    else:
                        self.stdout.write(self.style.WARNING(f"   ⚠️  Cache clear warning: {cache_result.stderr}"))
                except subprocess.TimeoutExpired:
                    self.stdout.write(self.style.WARNING("   ⚠️  Pip cache clear timed out"))
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"   ⚠️  Could not clear pip cache: {e}"))
                
                self.stdout.write(self.style.HTTP_INFO("\n💡 Recommendations after upgrade:"))
                self.stdout.write("   1. Run tests to ensure everything works correctly")
                self.stdout.write("   2. Run 'python manage.py check_dependencies' again to verify")
                self.stdout.write("   3. Consider running 'python manage.py detect_and_train' to retrain with new packages")
            
            return upgraded_packages

    def get_aiwaf_compatibility_constraints(self):
        """Get AIWAF's compatibility constraints to ensure stability"""
        return {
            'django': {
                'min_version': '3.2',
                'max_version': '99.0',  # AIWAF works with all Django versions
                'reason': 'AIWAF is compatible with Django 3.2+'
            },
            'numpy': {
                'min_version': '1.21',
                'max_version': '1.99.99',  # Avoid NumPy 2.0 breaking changes
                'reason': 'NumPy 2.0+ may cause compatibility issues'
            },
            'pandas': {
                'min_version': '1.3',
                'max_version': '2.9.99',
                'reason': 'AIWAF tested with pandas 1.3-2.x series'
            },
            'scikit-learn': {
                'min_version': '1.0',
                'max_version': '1.99.99',  # Stay in 1.x series
                'reason': 'AIWAF models trained with scikit-learn 1.x'
            },
            'joblib': {
                'min_version': '1.1',
                'max_version': '1.99.99',
                'reason': 'AIWAF compatible with joblib 1.x series'
            },
            'packaging': {
                'min_version': '21.0',
                'max_version': '99.0',
                'reason': 'Required for dependency checking'
            },
            'requests': {
                'min_version': '2.25.0',
                'max_version': '2.99.99',
                'reason': 'Required for PyPI API access'
            }
        }

    def plan_safe_upgrade(self, pkg, aiwaf_constraints, all_results):
        """Plan a safe upgrade for a package considering AIWAF compatibility"""
        pkg_name = pkg['name'].lower()
        current_version = pkg['installed']
        latest_version = pkg['latest']
        
        # Skip AIWAF itself
        if pkg_name == 'aiwaf':
            return {
                'package': pkg,
                'safe': False,
                'target_version': None,
                'reason': 'AIWAF should be upgraded separately using pip install --upgrade aiwaf'
            }
        
        # Check AIWAF constraints
        if pkg_name in aiwaf_constraints:
            constraint = aiwaf_constraints[pkg_name]
            max_version = constraint['max_version']
            
            try:
                if version.parse(latest_version) > version.parse(max_version):
                    # Find the highest safe version
                    safe_version = self.find_highest_safe_version(pkg_name, max_version)
                    if safe_version and version.parse(safe_version) > version.parse(current_version):
                        return {
                            'package': pkg,
                            'safe': True,
                            'target_version': safe_version,
                            'reason': f'Upgraded to latest safe version (AIWAF constraint: <={max_version})'
                        }
                    else:
                        return {
                            'package': pkg,
                            'safe': False,
                            'target_version': None,
                            'reason': f'{constraint["reason"]} (max safe: {max_version})'
                        }
                else:
                    # Latest version is within AIWAF constraints
                    # Check for other compatibility issues
                    compatibility_check = self.check_upgrade_compatibility(pkg, latest_version, all_results)
                    if compatibility_check['safe']:
                        return {
                            'package': pkg,
                            'safe': True,
                            'target_version': latest_version,
                            'reason': 'Safe to upgrade to latest version'
                        }
                    else:
                        return {
                            'package': pkg,
                            'safe': False,
                            'target_version': None,
                            'reason': compatibility_check['reason']
                        }
            except Exception as e:
                return {
                    'package': pkg,
                    'safe': False,
                    'target_version': None,
                    'reason': f'Version parsing error: {e}'
                }
        else:
            # No specific AIWAF constraints, check general compatibility
            compatibility_check = self.check_upgrade_compatibility(pkg, latest_version, all_results)
            return {
                'package': pkg,
                'safe': compatibility_check['safe'],
                'target_version': latest_version if compatibility_check['safe'] else None,
                'reason': compatibility_check['reason'] if not compatibility_check['safe'] else 'No known compatibility issues'
            }

    def find_highest_safe_version(self, package_name, max_version):
        """Find the highest version that's still within constraints"""
        try:
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json', timeout=10)
            if response.status_code == 200:
                data = response.json()
                releases = data.get('releases', {})
                
                safe_versions = []
                for ver in releases.keys():
                    try:
                        if version.parse(ver) <= version.parse(max_version):
                            safe_versions.append(ver)
                    except:
                        continue
                
                if safe_versions:
                    # Sort and return the highest safe version
                    safe_versions.sort(key=lambda x: version.parse(x), reverse=True)
                    return safe_versions[0]
        except Exception:
            pass
        return None

    def check_upgrade_compatibility(self, pkg, target_version, all_results):
        """Check if upgrading a package to target version would cause conflicts"""
        pkg_name = pkg['name'].lower()
        
        # Known problematic upgrade scenarios
        if pkg_name == 'numpy' and version.parse(target_version) >= version.parse('2.0.0'):
            # Check if pandas is compatible with NumPy 2.0
            pandas_pkg = next((p for p in all_results if p['name'].lower() == 'pandas'), None)
            if pandas_pkg and pandas_pkg['status'] != 'not_installed':
                pandas_version = pandas_pkg['installed']
                if version.parse(pandas_version) < version.parse('2.1.0'):
                    return {
                        'safe': False,
                        'reason': f'NumPy 2.0+ requires pandas 2.1+, but pandas {pandas_version} is installed'
                    }
        
        if pkg_name == 'pandas' and version.parse(target_version) >= version.parse('2.0.0'):
            # Check if NumPy is compatible
            numpy_pkg = next((p for p in all_results if p['name'].lower() == 'numpy'), None)
            if numpy_pkg and numpy_pkg['status'] != 'not_installed':
                numpy_version = numpy_pkg['installed']
                if version.parse(numpy_version) < version.parse('1.22.0'):
                    return {
                        'safe': False,
                        'reason': f'pandas 2.0+ requires NumPy 1.22+, but NumPy {numpy_version} is installed'
                    }
        
        return {'safe': True, 'reason': 'No compatibility issues detected'}

    def update_requirements_file(self, upgraded_packages):
        """Update requirements.txt with new package versions"""
        self.stdout.write(self.style.HTTP_INFO("\n📝 Updating requirements.txt..."))
        
        requirements_path = os.path.join(settings.BASE_DIR, 'requirements.txt')
        
        if not os.path.exists(requirements_path):
            self.stdout.write(self.style.WARNING(f"   ⚠️  requirements.txt not found at {requirements_path}"))
            self.stdout.write("   💡 You can create one manually with updated versions")
            return
        
        try:
            # Read current requirements.txt
            with open(requirements_path, 'r') as f:
                lines = f.readlines()
            
            # Create backup
            backup_path = requirements_path + '.backup'
            with open(backup_path, 'w') as f:
                f.writelines(lines)
            self.stdout.write(f"   📋 Backup created: {backup_path}")
            
            # Update lines with new versions
            updated_lines = []
            updated_count = 0
            
            for line in lines:
                original_line = line.strip()
                updated_line = line
                
                if original_line and not original_line.startswith('#'):
                    # Check if this line contains an upgraded package
                    for pkg in upgraded_packages:
                        pkg_name = pkg['name']
                        new_version = pkg['new_version']
                        
                        # Check various formats: package>=version, package==version, etc.
                        if self.line_contains_package(original_line, pkg_name):
                            # Update the line with new version
                            updated_line = self.update_package_line(original_line, pkg_name, new_version)
                            if updated_line != original_line:
                                updated_count += 1
                                self.stdout.write(f"   📦 {pkg_name}: {original_line} → {updated_line.strip()}")
                            break
                
                updated_lines.append(updated_line)
            
            # Write updated requirements.txt
            with open(requirements_path, 'w') as f:
                f.writelines(updated_lines)
            
            if updated_count > 0:
                self.stdout.write(self.style.SUCCESS(f"\n   ✅ Updated {updated_count} packages in requirements.txt"))
                self.stdout.write(f"   💾 Original backed up as: {backup_path}")
            else:
                self.stdout.write(self.style.NOTICE("   ℹ️  No package lines found to update in requirements.txt"))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"   ❌ Error updating requirements.txt: {e}"))

    def line_contains_package(self, line, package_name):
        """Check if a requirements line contains the specified package"""
        # Remove comments and whitespace
        line = line.split('#')[0].strip()
        if not line:
            return False
        
        # Check if line starts with package name followed by version specifier
        return (line.lower().startswith(package_name.lower()) and 
                len(line) > len(package_name) and 
                line[len(package_name)] in ['=', '<', '>', '!', '~', ' ', '\t'])

    def update_package_line(self, line, package_name, new_version):
        """Update a requirements line with new package version"""
        # Split line into package part and comment part
        parts = line.split('#', 1)
        package_part = parts[0].strip()
        comment_part = f" #{parts[1]}" if len(parts) > 1 else ""
        
        # Extract package name and update with new version
        # Use >= to allow for future compatible versions
        updated_package = f"{package_name}>={new_version}"
        
        return updated_package + comment_part + '\n'

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
