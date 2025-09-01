#!/usr/bin/env python3
"""
AndroidManifest.xml Analyzer
Extracts and analyzes Android manifest information
"""

import xml.etree.ElementTree as ET
import subprocess
from pathlib import Path

class ManifestAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        self.manifest_path = self.extract_dir / "AndroidManifest.xml"
        
    def analyze(self):
        """Analyze AndroidManifest.xml"""
        results = {
            "exists": False,
            "readable": False,
            "package_name": "",
            "version_code": "",
            "version_name": "",
            "min_sdk": "",
            "target_sdk": "",
            "compile_sdk": "",
            "permissions": [],
            "dangerous_permissions": [],
            "exported_components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": []
            },
            "security_flags": {
                "debuggable": False,
                "allow_backup": True,
                "uses_cleartext_traffic": False,
                "network_security_config": ""
            },
            "intent_filters": [],
            "meta_data": [],
            "errors": []
        }
        
        try:
            # Check if manifest exists
            results["exists"] = self.manifest_path.exists()
            
            if not results["exists"]:
                results["errors"].append("AndroidManifest.xml not found")
                return results
            
            # Try to parse the manifest
            manifest_content = self._read_manifest()
            if manifest_content:
                results["readable"] = True
                self._parse_manifest(manifest_content, results)
            else:
                results["errors"].append("Could not read AndroidManifest.xml")
                
        except Exception as e:
            results["errors"].append(f"Manifest analysis error: {str(e)}")
            
        return results
    
    def _read_manifest(self):
        """Read AndroidManifest.xml (try binary and text formats)"""
        try:
            # Try parsing as XML directly (if decompiled)
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try using aapt to dump manifest if binary
            try:
                # Find the original APK file - check multiple possible locations
                possible_apk_paths = []
                
                # Check current directory and parent directories for APK files
                current_dir = self.extract_dir
                for _ in range(5):  # Go up 5 levels max
                    apk_files = list(current_dir.glob("*.apk"))
                    if apk_files:
                        possible_apk_paths.extend(apk_files)
                        break
                    current_dir = current_dir.parent
                    if current_dir == current_dir.parent:  # Reached root
                        break
                
                # Also check common locations
                common_paths = [
                    Path.cwd() / "*.apk",
                    Path.home() / "*.apk",
                    Path("/tmp") / "*.apk"
                ]
                
                for path_pattern in common_paths:
                    if path_pattern.name == "*.apk":
                        apk_files = list(path_pattern.parent.glob("*.apk"))
                        possible_apk_paths.extend(apk_files)
                    elif path_pattern.exists():
                        possible_apk_paths.append(path_pattern)
                
                apk_path = None
                for path_pattern in possible_apk_paths:
                    if path_pattern.name == "*.apk":
                        apk_files = list(path_pattern.parent.glob("*.apk"))
                        if apk_files:
                            apk_path = apk_files[0]
                            break
                    elif path_pattern.exists():
                        apk_path = path_pattern
                        break
                
                if apk_path:
                    # Try aapt dump badging first (gives better readable values)
                    result = subprocess.run(['aapt', 'dump', 'badging', str(apk_path)], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return result.stdout
                    
                    # Try aapt dump xmltree as fallback
                    result = subprocess.run(['aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return result.stdout
            except Exception as e:
                print(f"Warning: aapt failed: {e}")
                
            # Try using apktool if available
            try:
                # Find APK file using the same logic as above
                apk_path = None
                current_dir = self.extract_dir
                for _ in range(5):  # Go up 5 levels max
                    apk_files = list(current_dir.glob("*.apk"))
                    if apk_files:
                        apk_path = apk_files[0]
                        break
                    current_dir = current_dir.parent
                    if current_dir == current_dir.parent:  # Reached root
                        break
                
                if apk_path:
                    result = subprocess.run(['apktool', 'd', '-f', '-o', 
                                           str(self.extract_dir / 'apktool_output'),
                                           str(apk_path)], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        apktool_manifest = self.extract_dir / 'apktool_output' / 'AndroidManifest.xml'
                        if apktool_manifest.exists():
                            with open(apktool_manifest, 'r', encoding='utf-8') as f:
                                return f.read()
            except Exception as e:
                print(f"Warning: apktool failed: {e}")
                
        return None
    
    def _parse_manifest(self, content, results):
        """Parse manifest content"""
        try:
            # Parse XML
            root = ET.fromstring(content)
            
            # Extract package info
            results["package_name"] = root.get('package', '')
            results["version_code"] = root.get('{http://schemas.android.com/apk/res/android}versionCode', '')
            results["version_name"] = root.get('{http://schemas.android.com/apk/res/android}versionName', '')
            
            # Extract SDK versions
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                results["min_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '')
                results["target_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '')
            
            # Extract permissions
            self._extract_permissions(root, results)
            
            # Extract application info
            app = root.find('application')
            if app is not None:
                self._extract_application_info(app, results)
                
        except ET.ParseError:
            # If XML parsing fails, try text parsing
            self._parse_manifest_text(content, results)
        
        # If still no data, try aapt badging format
        if not results.get("package_name") and "package:" in content:
            self._parse_aapt_badging(content, results)
    
    def _extract_permissions(self, root, results):
        """Extract permissions from manifest with improved filtering"""
        # More specific dangerous permissions list
        dangerous_perms = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 
            'READ_CALENDAR', 'WRITE_CALENDAR',
            'READ_CALL_LOG', 'WRITE_CALL_LOG', 
            'CAMERA', 'RECORD_AUDIO',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 
            'ACCESS_BACKGROUND_LOCATION',
            'READ_PHONE_STATE', 'CALL_PHONE', 
            'READ_SMS', 'SEND_SMS', 'WRITE_SMS',
            'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE', 
            'BODY_SENSORS', 'READ_PHONE_NUMBERS',
            'PROCESS_OUTGOING_CALLS', 'MODIFY_PHONE_STATE'
        ]
        
        # Common safe permissions that should not be flagged
        safe_perms = [
            'INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE',
            'WAKE_LOCK', 'VIBRATE', 'RECEIVE_BOOT_COMPLETED',
            'WRITE_SETTINGS', 'READ_SETTINGS', 'SYSTEM_ALERT_WINDOW',
            'REQUEST_INSTALL_PACKAGES', 'REQUEST_DELETE_PACKAGES',
            'QUERY_ALL_PACKAGES', 'PACKAGE_USAGE_STATS'
        ]
        
        for perm in root.findall('uses-permission'):
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
            if perm_name:
                results["permissions"].append(perm_name)
                
                # Skip safe permissions
                if any(safe_perm in perm_name for safe_perm in safe_perms):
                    continue
                
                # Check if dangerous
                for dangerous in dangerous_perms:
                    if dangerous in perm_name:
                        results["dangerous_permissions"].append(perm_name)
                        break
    
    def _extract_application_info(self, app, results):
        """Extract application-level information with improved defaults"""
        # Security flags with better default handling
        debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
        results["security_flags"]["debuggable"] = debuggable.lower() == 'true'
        
        # allowBackup default is true, but we should check if it's explicitly set
        allow_backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
        results["security_flags"]["allow_backup"] = allow_backup.lower() == 'true'
        
        # usesCleartextTraffic default is false for API 28+
        uses_cleartext = app.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic', 'false')
        results["security_flags"]["uses_cleartext_traffic"] = uses_cleartext.lower() == 'true'
        
        results["security_flags"]["network_security_config"] = app.get(
            '{http://schemas.android.com/apk/res/android}networkSecurityConfig', '')
        
        # Extract components
        self._extract_components(app, results)
    
    def _extract_components(self, app, results):
        """Extract exported components with improved filtering"""
        # Activities
        for activity in app.findall('activity'):
            exported = activity.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
            
            # Check for intent filters (auto-exported)
            has_intent_filter = len(activity.findall('intent-filter')) > 0
            
            # Only mark as exported if explicitly set or has specific intent filters
            is_exported = exported.lower() == 'true'
            is_auto_exported = has_intent_filter and self._is_risky_intent_filter(activity)
            
            if is_exported or is_auto_exported:
                component_info = {
                    "name": name,
                    "exported": is_exported,
                    "auto_exported": is_auto_exported,
                    "has_intent_filter": has_intent_filter,
                    "intent_filters": self._extract_intent_filters(activity),
                    "risk_level": self._assess_component_risk(activity, name, "activity")
                }
                results["exported_components"]["activities"].append(component_info)
        
        # Services
        for service in app.findall('service'):
            exported = service.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            name = service.get('{http://schemas.android.com/apk/res/android}name', '')
            has_intent_filter = len(service.findall('intent-filter')) > 0
            
            is_exported = exported.lower() == 'true'
            is_auto_exported = has_intent_filter and self._is_risky_intent_filter(service)
            
            if is_exported or is_auto_exported:
                component_info = {
                    "name": name,
                    "exported": is_exported,
                    "auto_exported": is_auto_exported,
                    "has_intent_filter": has_intent_filter,
                    "intent_filters": self._extract_intent_filters(service),
                    "risk_level": self._assess_component_risk(service, name, "service")
                }
                results["exported_components"]["services"].append(component_info)
        
        # Receivers
        for receiver in app.findall('receiver'):
            exported = receiver.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            name = receiver.get('{http://schemas.android.com/apk/res/android}name', '')
            has_intent_filter = len(receiver.findall('intent-filter')) > 0
            
            is_exported = exported.lower() == 'true'
            is_auto_exported = has_intent_filter and self._is_risky_intent_filter(receiver)
            
            if is_exported or is_auto_exported:
                component_info = {
                    "name": name,
                    "exported": is_exported,
                    "auto_exported": is_auto_exported,
                    "has_intent_filter": has_intent_filter,
                    "intent_filters": self._extract_intent_filters(receiver),
                    "risk_level": self._assess_component_risk(receiver, name, "receiver")
                }
                results["exported_components"]["receivers"].append(component_info)
        
        # Providers
        for provider in app.findall('provider'):
            exported = provider.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
            authorities = provider.get('{http://schemas.android.com/apk/res/android}authorities', '')
            
            if exported.lower() == 'true':
                component_info = {
                    "name": name,
                    "exported": True,
                    "auto_exported": False,
                    "authorities": authorities,
                    "risk_level": self._assess_component_risk(provider, name, "provider")
                }
                results["exported_components"]["providers"].append(component_info)
    
    def _extract_intent_filters(self, component):
        """Extract intent filters from component"""
        filters = []
        for intent_filter in component.findall('intent-filter'):
            filter_info = {
                "actions": [],
                "categories": [],
                "data": []
            }
            
            for action in intent_filter.findall('action'):
                action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                if action_name:
                    filter_info["actions"].append(action_name)
            
            for category in intent_filter.findall('category'):
                cat_name = category.get('{http://schemas.android.com/apk/res/android}name', '')
                if cat_name:
                    filter_info["categories"].append(cat_name)
            
            for data in intent_filter.findall('data'):
                data_info = {}
                for attr in ['scheme', 'host', 'port', 'path', 'pathPattern', 'pathPrefix', 'mimeType']:
                    value = data.get(f'{{http://schemas.android.com/apk/res/android}}{attr}', '')
                    if value:
                        data_info[attr] = value
                if data_info:
                    filter_info["data"].append(data_info)
            
            filters.append(filter_info)
        
        return filters
    
    def _is_risky_intent_filter(self, component):
        """Check if intent filter poses security risks"""
        for intent_filter in component.findall('intent-filter'):
            # Check for dangerous actions
            dangerous_actions = [
                'android.intent.action.VIEW',
                'android.intent.action.SEND',
                'android.intent.action.SENDTO',
                'android.intent.action.PICK',
                'android.intent.action.GET_CONTENT',
                'android.intent.action.CALL',
                'android.intent.action.DIAL'
            ]
            
            for action in intent_filter.findall('action'):
                action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                if action_name in dangerous_actions:
                    return True
            
            # Check for dangerous categories
            dangerous_categories = [
                'android.intent.category.DEFAULT',
                'android.intent.category.BROWSABLE'
            ]
            
            for category in intent_filter.findall('category'):
                cat_name = category.get('{http://schemas.android.com/apk/res/android}name', '')
                if cat_name in dangerous_categories:
                    return True
        
        return False
    
    def _assess_component_risk(self, component, name, component_type):
        """Assess the risk level of a component"""
        risk_level = "low"
        
        # Check for common safe component names
        safe_names = [
            'MainActivity', 'SplashActivity', 'LauncherActivity', 'HomeActivity',
            'LoginActivity', 'RegisterActivity', 'SettingsActivity',
            'MainService', 'NotificationService', 'BackgroundService',
            'BootReceiver', 'NetworkReceiver', 'PackageReceiver'
        ]
        
        # Check if it's a safe component
        if any(safe_name.lower() in name.lower() for safe_name in safe_names):
            risk_level = "low"
        else:
            # Check for risky patterns
            risky_patterns = [
                'webview', 'browser', 'file', 'content', 'provider',
                'share', 'send', 'upload', 'download', 'export'
            ]
            
            if any(pattern in name.lower() for pattern in risky_patterns):
                risk_level = "medium"
            
            # Check for explicitly exported components
            exported = component.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            if exported.lower() == 'true':
                risk_level = "high"
            
            # Check for providers without authorities
            if component_type == "provider":
                authorities = component.get('{http://schemas.android.com/apk/res/android}authorities', '')
                if not authorities:
                    risk_level = "high"
        
        return risk_level
    
    def _parse_manifest_text(self, content, results):
        """Parse manifest from text dump (improved method)"""
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract package name
            if 'package=' in line:
                try:
                    package = line.split('package=')[1].split()[0].strip('"\'')
                    results["package_name"] = package
                except:
                    pass
            
            # Extract version code
            if 'android:versionCode(' in line:
                try:
                    version_code = line.split('android:versionCode(')[1].split(')')[0]
                    # Convert hex to decimal if needed
                    if version_code.startswith('0x'):
                        version_code = str(int(version_code, 16))
                    results["version_code"] = version_code
                except:
                    pass
            
            # Extract version name
            if 'android:versionName(' in line:
                try:
                    version_name = line.split('android:versionName(')[1].split(')')[0].strip('"\'')
                    # Convert hex to decimal if needed
                    if version_name.startswith('0x'):
                        version_name = str(int(version_name, 16))
                    results["version_name"] = version_name
                except:
                    pass
            
            # Extract min SDK
            if 'android:minSdkVersion(' in line:
                try:
                    min_sdk = line.split('android:minSdkVersion(')[1].split(')')[0]
                    # Convert hex to decimal if needed
                    if min_sdk.startswith('0x'):
                        min_sdk = str(int(min_sdk, 16))
                    results["min_sdk"] = min_sdk
                except:
                    pass
            
            # Extract target SDK
            if 'android:targetSdkVersion(' in line:
                try:
                    target_sdk = line.split('android:targetSdkVersion(')[1].split(')')[0]
                    # Convert hex to decimal if needed
                    if target_sdk.startswith('0x'):
                        target_sdk = str(int(target_sdk, 16))
                    results["target_sdk"] = target_sdk
                except:
                    pass
            
            # Extract compile SDK
            if 'android:compileSdkVersion(' in line:
                try:
                    compile_sdk = line.split('android:compileSdkVersion(')[1].split(')')[0]
                    # Convert hex to decimal if needed
                    if compile_sdk.startswith('0x'):
                        compile_sdk = str(int(compile_sdk, 16))
                    results["compile_sdk"] = compile_sdk
                except:
                    pass
            
            # Extract security flags
            if 'android:debuggable(' in line:
                try:
                    debuggable = line.split('android:debuggable(')[1].split(')')[0]
                    results["security_flags"]["debuggable"] = debuggable == '0xffffffff'
                except:
                    pass
            
            if 'android:allowBackup(' in line:
                try:
                    allow_backup = line.split('android:allowBackup(')[1].split(')')[0]
                    results["security_flags"]["allow_backup"] = allow_backup == '0xffffffff'
                except:
                    pass
            
            if 'android:usesCleartextTraffic(' in line:
                try:
                    uses_cleartext = line.split('android:usesCleartextTraffic(')[1].split(')')[0]
                    results["security_flags"]["uses_cleartext_traffic"] = uses_cleartext == '0xffffffff'
                except:
                    pass
            
            if 'android:networkSecurityConfig(' in line:
                try:
                    network_config = line.split('android:networkSecurityConfig(')[1].split(')')[0]
                    results["security_flags"]["network_security_config"] = network_config
                except:
                    pass
            
            # Extract permissions
            if 'android:name(' in line and 'android.permission.' in line:
                try:
                    perm = line.split('="')[1].split('"')[0]
                    results["permissions"].append(perm)
                    
                    # Check if dangerous (simplified list)
                    dangerous_perms = [
                        'READ_CONTACTS', 'WRITE_CONTACTS', 'CAMERA', 'RECORD_AUDIO',
                        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 
                        'READ_PHONE_STATE', 'CALL_PHONE', 'READ_SMS', 'SEND_SMS',
                        'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE'
                    ]
                    
                    for dangerous in dangerous_perms:
                        if dangerous in perm:
                            results["dangerous_permissions"].append(perm)
                            break
                except:
                    pass
            
            # Extract exported components
            if 'android:name(' in line and 'activity' in line:
                try:
                    component_name = line.split('="')[1].split('"')[0]
                    
                    # Check if exported (look for 0xffffffff which means true)
                    exported = False
                    if 'android:exported(' in content and '0xffffffff' in content:
                        exported = True
                    
                    # Add to activities (simplified)
                    component_info = {
                        "name": component_name,
                        "exported": exported,
                        "auto_exported": False,
                        "has_intent_filter": False,
                        "risk_level": "low"
                    }
                    
                    results["exported_components"]["activities"].append(component_info)
                except:
                    pass
            
            # Extract services
            elif 'android:name(' in line and 'service' in line:
                try:
                    component_name = line.split('="')[1].split('"')[0]
                    
                    exported = False
                    if 'android:exported(' in content and '0xffffffff' in content:
                        exported = True
                    
                    component_info = {
                        "name": component_name,
                        "exported": exported,
                        "auto_exported": False,
                        "has_intent_filter": False,
                        "risk_level": "low"
                    }
                    
                    results["exported_components"]["services"].append(component_info)
                except:
                    pass
            
            # Extract receivers
            elif 'android:name(' in line and 'receiver' in line:
                try:
                    component_name = line.split('="')[1].split('"')[0]
                    
                    exported = False
                    if 'android:exported(' in content and '0xffffffff' in content:
                        exported = True
                    
                    component_info = {
                        "name": component_name,
                        "exported": exported,
                        "auto_exported": False,
                        "has_intent_filter": False,
                        "risk_level": "low"
                    }
                    
                    results["exported_components"]["receivers"].append(component_info)
                except:
                    pass
            
            # Extract providers
            elif 'android:name(' in line and 'provider' in line:
                try:
                    component_name = line.split('="')[1].split('"')[0]
                    
                    exported = False
                    if 'android:exported(' in content and '0xffffffff' in content:
                        exported = True
                    
                    component_info = {
                        "name": component_name,
                        "exported": exported,
                        "auto_exported": False,
                        "has_intent_filter": False,
                        "risk_level": "low"
                    }
                    
                    results["exported_components"]["providers"].append(component_info)
                except:
                    pass
    
    def _parse_aapt_badging(self, content, results):
        """Parse aapt dump badging output"""
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract package name
            if line.startswith('package:'):
                try:
                    # Format: package: name='com.example.app' versionCode='1' versionName='1.0'
                    parts = line.split()
                    for part in parts:
                        if part.startswith("name='"):
                            results["package_name"] = part.split("'")[1]
                        elif part.startswith("versionCode='"):
                            version_code = part.split("'")[1]
                            # Convert hex to decimal if needed
                            if version_code.startswith('0x'):
                                version_code = str(int(version_code, 16))
                            results["version_code"] = version_code
                        elif part.startswith("versionName='"):
                            version_name = part.split("'")[1]
                            # Convert hex to decimal if needed
                            if version_name.startswith('0x'):
                                version_name = str(int(version_name, 16))
                            results["version_name"] = version_name
                except:
                    pass
            
            # Extract SDK versions
            elif line.startswith('sdkVersion:'):
                try:
                    # Format: sdkVersion:'21'
                    sdk = line.split("'")[1]
                    results["min_sdk"] = sdk
                except:
                    pass
            
            elif line.startswith('targetSdkVersion:'):
                try:
                    # Format: targetSdkVersion:'30'
                    sdk = line.split("'")[1]
                    results["target_sdk"] = sdk
                except:
                    pass
            
            # Extract permissions
            elif line.startswith('uses-permission:'):
                try:
                    # Format: uses-permission: name='android.permission.INTERNET'
                    perm = line.split("name='")[1].split("'")[0]
                    results["permissions"].append(perm)
                    
                    # Check if dangerous
                    dangerous_perms = [
                        'READ_CONTACTS', 'WRITE_CONTACTS', 'CAMERA', 'RECORD_AUDIO',
                        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 
                        'READ_PHONE_STATE', 'CALL_PHONE', 'READ_SMS', 'SEND_SMS',
                        'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE'
                    ]
                    
                    for dangerous in dangerous_perms:
                        if dangerous in perm:
                            results["dangerous_permissions"].append(perm)
                            break
                except:
                    pass
            
            # Extract application info
            elif line.startswith('application:'):
                try:
                    # Format: application: label='App Name' icon='res/mipmap-hdpi/ic_launcher.png'
                    if "label='" in line:
                        label = line.split("label='")[1].split("'")[0]
                        results["app_label"] = label
                except:
                    pass
            
            # Extract activities
            elif line.startswith('activity:'):
                try:
                    # Format: activity: name='com.example.MainActivity'
                    activity_name = line.split("name='")[1].split("'")[0]
                    
                    # Check if exported (look for exported='true')
                    exported = 'exported=\'true\'' in line
                    
                    component_info = {
                        "name": activity_name,
                        "exported": exported,
                        "auto_exported": False,
                        "has_intent_filter": False,
                        "risk_level": "high" if exported else "low"
                    }
                    results["exported_components"]["activities"].append(component_info)
                except:
                    pass