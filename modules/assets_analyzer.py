#!/usr/bin/env python3
"""
Assets and Resources Analyzer
Analyzes assets, resources and other files in APK
"""

import os
import re
import json
import base64
from pathlib import Path

class AssetsAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze assets and resources"""
        results = {
            "assets": {
                "exists": False,
                "files": [],
                "total_size": 0,
                "suspicious_files": []
            },
            "resources": {
                "exists": False,
                "files": [],
                "total_size": 0,
                "strings": [],
                "urls": [],
                "suspicious_files": []
            },
            "raw": {
                "exists": False,
                "files": []
            },
            "configs": [],
            "secrets_found": [],
            "base64_data": [],
            "errors": []
        }
        
        try:
            # Analyze assets directory
            assets_dir = self.extract_dir / "assets"
            if assets_dir.exists():
                results["assets"] = self._analyze_directory(assets_dir, "assets")
            
            # Analyze resources directory
            res_dir = self.extract_dir / "res"
            if res_dir.exists():
                results["resources"] = self._analyze_directory(res_dir, "resources")
                # Extract strings from resources
                results["resources"]["strings"] = self._extract_resource_strings(res_dir)
            
            # Analyze raw directory
            raw_dir = self.extract_dir / "res" / "raw"
            if raw_dir.exists():
                results["raw"] = self._analyze_directory(raw_dir, "raw")
            
            # Analyze OBB files if present (from XAPK)
            obb_dir = self.extract_dir.parent / "obb_files"
            if obb_dir.exists():
                results["obb_files"] = self._analyze_obb_files(obb_dir)
            
            # Look for configuration files throughout the APK
            results["configs"] = self._find_config_files()
            
            # Search for secrets in all text files
            results["secrets_found"] = self._search_secrets()
            
            # Look for base64 encoded data
            results["base64_data"] = self._find_base64_data()
            
        except Exception as e:
            results["errors"].append(f"Assets analysis error: {str(e)}")
            
        return results
    
    def _analyze_obb_files(self, obb_dir):
        """Analyze OBB (Opaque Binary Blob) files from XAPK"""
        obb_info = {
            "exists": True,
            "files": [],
            "total_size": 0,
            "suspicious_files": [],
            "analysis": []
        }
        
        try:
            for obb_file in obb_dir.glob("*.obb"):
                file_info = {
                    "name": obb_file.name,
                    "size": obb_file.stat().st_size,
                    "size_mb": obb_file.stat().st_size / (1024 * 1024)
                }
                
                obb_info["files"].append(file_info)
                obb_info["total_size"] += file_info["size"]
                
                # Analyze OBB file content
                obb_analysis = self._analyze_obb_content(obb_file)
                obb_info["analysis"].append(obb_analysis)
                
        except Exception as e:
            obb_info["errors"] = [f"OBB analysis error: {str(e)}"]
            
        return obb_info
    
    def _analyze_obb_content(self, obb_file):
        """Analyze content of OBB file"""
        analysis = {
            "file": obb_file.name,
            "type": "unknown",
            "content_summary": "",
            "suspicious_content": []
        }
        
        try:
            # Try to read first few bytes to determine type
            with open(obb_file, 'rb') as f:
                header = f.read(16)
                
            # Check if it's a ZIP file (common for OBB)
            if header.startswith(b'PK'):
                analysis["type"] = "zip_archive"
                analysis["content_summary"] = "ZIP archive (likely contains game assets)"
                
                # Try to list contents
                import zipfile
                try:
                    with zipfile.ZipFile(obb_file, 'r') as zip_file:
                        file_list = zip_file.namelist()
                        analysis["content_summary"] = f"ZIP archive with {len(file_list)} files"
                        
                        # Look for suspicious files
                        suspicious_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.dat']
                        for file_name in file_list:
                            if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                                analysis["suspicious_content"].append(file_name)
                                
                except Exception:
                    analysis["content_summary"] = "ZIP archive (corrupted or encrypted)"
                    
            elif header.startswith(b'\x1f\x8b'):
                analysis["type"] = "gzip_archive"
                analysis["content_summary"] = "GZIP compressed archive"
                
            elif header.startswith(b'BZh'):
                analysis["type"] = "bzip2_archive"
                analysis["content_summary"] = "BZIP2 compressed archive"
                
            else:
                analysis["type"] = "binary_data"
                analysis["content_summary"] = "Binary data (unknown format)"
                
        except Exception as e:
            analysis["content_summary"] = f"Error analyzing file: {str(e)}"
            
        return analysis
    
    def _analyze_directory(self, directory, dir_type):
        """Analyze a specific directory"""
        dir_info = {
            "exists": True,
            "files": [],
            "total_size": 0,
            "suspicious_files": []
        }
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(self.extract_dir)
                    
                    file_info = {
                        "path": str(rel_path),
                        "name": file,
                        "size": file_path.stat().st_size,
                        "extension": file_path.suffix.lower(),
                        "type": self._get_file_type(file_path)
                    }
                    
                    dir_info["files"].append(file_info)
                    dir_info["total_size"] += file_info["size"]
                    
                    # Check for suspicious files
                    if self._is_suspicious_file(file_info):
                        dir_info["suspicious_files"].append(file_info)
                        
        except Exception as e:
            dir_info["error"] = str(e)
            
        return dir_info
    
    def _get_file_type(self, file_path):
        """Determine file type"""
        extension = file_path.suffix.lower()
        
        type_map = {
            '.json': 'JSON',
            '.xml': 'XML',
            '.txt': 'Text',
            '.properties': 'Properties',
            '.conf': 'Configuration',
            '.cfg': 'Configuration',
            '.ini': 'Configuration',
            '.yml': 'YAML',
            '.yaml': 'YAML',
            '.db': 'Database',
            '.sqlite': 'SQLite Database',
            '.sql': 'SQL',
            '.png': 'Image',
            '.jpg': 'Image',
            '.jpeg': 'Image',
            '.gif': 'Image',
            '.webp': 'Image',
            '.so': 'Native Library',
            '.jar': 'Java Archive',
            '.dex': 'DEX File',
            '.bin': 'Binary',
            '.dat': 'Data File'
        }
        
        return type_map.get(extension, 'Unknown')
    
    def _is_suspicious_file(self, file_info):
        """Check if file is suspicious with improved filtering"""
        
        # Skip common Android files that are not suspicious
        safe_android_files = [
            'strings.xml', 'colors.xml', 'dimens.xml', 'styles.xml',
            'themes.xml', 'attrs.xml', 'drawable', 'layout', 'menu',
            'values', 'mipmap', 'anim', 'animator', 'interpolator'
        ]
        
        file_path_lower = file_info["path"].lower()
        file_name_lower = file_info["name"].lower()
        
        # Skip standard Android resource files
        if any(safe_file in file_path_lower for safe_file in safe_android_files):
            return False
        
        # Skip common library files
        if any(lib in file_path_lower for lib in ['firebase', 'google', 'androidx', 'android']):
            return False
        
        suspicious_indicators = [
            # Highly suspicious extensions (crypto/security related)
            file_info["extension"] in ['.key', '.pem', '.p12', '.jks', '.keystore'],
            
            # Suspicious names with context
            any(keyword in file_name_lower for keyword in 
                ['secret', 'private', 'credential', 'password', 'token']),
            
            # Hidden files (but not Android hidden files)
            file_name_lower.startswith('.') and not file_name_lower.startswith('.android'),
            
            # Very large text files (over 100KB)
            file_info["type"] in ['Text', 'JSON', 'XML'] and file_info["size"] > 100000,
            
            # Executable files in assets (but not native libs in lib/ directory)
            file_info["extension"] in ['.exe', '.bin'] or 
            (file_info["extension"] in ['.so', '.dex', '.jar'] and 'lib/' not in file_path_lower)
        ]
        
        return any(suspicious_indicators)
    
    def _extract_resource_strings(self, res_dir):
        """Extract strings from resource files"""
        strings = []
        
        try:
            # Look for strings.xml files
            for strings_file in res_dir.rglob("strings.xml"):
                try:
                    with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Extract string values
                    string_pattern = r'<string[^>]*name="([^"]*)"[^>]*>([^<]*)</string>'
                    matches = re.findall(string_pattern, content)
                    
                    for name, value in matches:
                        if value and len(value.strip()) > 0:
                            strings.append({
                                "name": name,
                                "value": value.strip(),
                                "file": str(strings_file.relative_to(self.extract_dir))
                            })
                            
                except Exception:
                    continue
                    
        except Exception:
            pass
            
        return strings
    
    def _find_config_files(self):
        """Find configuration files throughout the APK"""
        configs = []
        
        config_patterns = [
            "*.json", "*.xml", "*.properties", "*.conf", 
            "*.cfg", "*.ini", "*.yml", "*.yaml"
        ]
        
        try:
            for pattern in config_patterns:
                for config_file in self.extract_dir.rglob(pattern):
                    if config_file.stat().st_size < 100000:  # Limit size
                        try:
                            content = self._read_file_safely(config_file)
                            if content and self._contains_sensitive_data(content):
                                configs.append({
                                    "path": str(config_file.relative_to(self.extract_dir)),
                                    "size": config_file.stat().st_size,
                                    "type": self._get_file_type(config_file),
                                    "preview": content[:500] + "..." if len(content) > 500 else content
                                })
                        except Exception:
                            continue
                            
        except Exception:
            pass
            
        return configs[:20]  # Limit results
    
    def _search_secrets(self):
        """Search for hardcoded secrets in files with improved filtering"""
        secrets = []
        
        # Define secret patterns with better specificity
        secret_patterns = [
            # API Keys with specific patterns
            (r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'API Key'),
            (r'["\']?(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Secret Key'),
            (r'["\']?(?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Access Token'),
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password'),
            
            # Specific service API keys
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Key'),
            (r'rk_live_[0-9a-zA-Z]{24}', 'Stripe Restricted Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'ya29\.[0-9A-Za-z\-_]+', 'OAuth Access Token'),
            
            # More specific hash patterns (avoid partial matches)
            (r'\b[0-9a-f]{32}\b(?![0-9a-f])', 'MD5 Hash'),
            (r'\b[0-9a-f]{40}\b(?![0-9a-f])', 'SHA1 Hash'),
            (r'\b[0-9a-f]{64}\b(?![0-9a-f])', 'SHA256 Hash')
        ]
        
        try:
            # Search in text files (exclude Android resource files)
            text_files = []
            for ext in ['.xml', '.json', '.txt', '.properties', '.java', '.js']:
                for text_file in self.extract_dir.rglob(f"*{ext}"):
                    # Skip Android resource files to reduce false positives
                    file_path = str(text_file.relative_to(self.extract_dir))
                    if any(skip_path in file_path.lower() for skip_path in [
                        'res/values/', 'res/layout/', 'res/drawable/', 'res/menu/',
                        'res/anim/', 'res/animator/', 'res/interpolator/',
                        'mipmap', 'androidx', 'android'
                    ]):
                        continue
                    text_files.append(text_file)
            
            for text_file in text_files[:30]:  # Reduced limit
                try:
                    content = self._read_file_safely(text_file)
                    if not content:
                        continue
                    
                    # Skip files that are too short or too long
                    if len(content) < 50 or len(content) > 100000:
                        continue
                        
                    for pattern, secret_type in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            
                            # Additional validation for secrets
                            if self._is_valid_secret(match, secret_type, content):
                                secrets.append({
                                    "type": secret_type,
                                    "value": match[:50] + "..." if len(match) > 50 else match,
                                    "file": str(text_file.relative_to(self.extract_dir)),
                                    "pattern": pattern
                                })
                                
                except Exception:
                    continue
                    
        except Exception:
            pass
            
        return secrets[:30]  # Reduced limit
    
    def _is_valid_secret(self, match, secret_type, content):
        """Validate if a matched string is actually a secret"""
        
        # Minimum length check
        if len(match) < 8:
            return False
        
        # Skip common false positives
        false_positive_patterns = [
            # Common words that might match hash patterns
            '00000000000000000000000000000000',  # All zeros
            'ffffffffffffffffffffffffffffffff',  # All f's
            'deadbeefdeadbeefdeadbeefdeadbeef',  # Dead beef
            'cafebabecafebabecafebabecafebabe',  # Cafe babe
            
            # Common test/placeholder values
            'test', 'example', 'sample', 'placeholder', 'dummy',
            '123456', 'password', 'admin', 'root', 'user',
            
            # Common Android resource values
            'app_name', 'hello_world', 'action_settings',
            'title_activity_main', 'menu_main', 'action_example'
        ]
        
        match_lower = match.lower()
        if any(fp in match_lower for fp in false_positive_patterns):
            return False
        
        # Check if it's just a simple alphanumeric string
        if match.isalnum() and len(match) < 16:
            return False
        
        # For hash patterns, ensure they're not part of longer strings
        if secret_type in ['MD5 Hash', 'SHA1 Hash', 'SHA256 Hash']:
            # Check if it's surrounded by other hex characters
            content_lower = content.lower()
            match_index = content_lower.find(match_lower)
            if match_index > 0:
                # Check character before
                if content_lower[match_index - 1] in '0123456789abcdef':
                    return False
            if match_index + len(match) < len(content_lower):
                # Check character after
                if content_lower[match_index + len(match)] in '0123456789abcdef':
                    return False
        
        return True
    
    def _find_base64_data(self):
        """Find Base64 encoded data with improved filtering"""
        base64_data = []
        
        try:
            text_files = []
            for ext in ['.xml', '.json', '.txt', '.properties']:
                for text_file in self.extract_dir.rglob(f"*{ext}"):
                    # Skip Android resource files
                    file_path = str(text_file.relative_to(self.extract_dir))
                    if any(skip_path in file_path.lower() for skip_path in [
                        'res/values/', 'res/layout/', 'res/drawable/', 'res/menu/',
                        'mipmap', 'androidx', 'android'
                    ]):
                        continue
                    text_files.append(text_file)
            
            for text_file in text_files[:20]:  # Reduced limit
                try:
                    content = self._read_file_safely(text_file)
                    if not content:
                        continue
                    
                    # Skip files that are too short
                    if len(content) < 100:
                        continue
                    
                    # Look for Base64 patterns (longer minimum length)
                    base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
                    matches = re.findall(base64_pattern, content)
                    
                    for match in matches:
                        if len(match) >= 50:  # Increased minimum length
                            try:
                                # Try to decode
                                decoded = base64.b64decode(match + "===")
                                if self._is_printable(decoded[:100]) and self._is_interesting_base64(decoded):
                                    base64_data.append({
                                        "encoded": match[:50] + "..." if len(match) > 50 else match,
                                        "decoded_preview": decoded[:100].decode('utf-8', errors='ignore'),
                                        "file": str(text_file.relative_to(self.extract_dir)),
                                        "length": len(match)
                                    })
                            except Exception:
                                continue
                                
                except Exception:
                    continue
                    
        except Exception:
            pass
            
        return base64_data[:10]  # Reduced limit
    
    def _read_file_safely(self, file_path):
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
    
    def _contains_sensitive_data(self, content):
        """Check if content contains potentially sensitive data with improved filtering"""
        # More specific sensitive keywords to reduce false positives
        sensitive_keywords = [
            'api_key', 'secret_key', 'access_token', 'auth_token', 'private_key',
            'password', 'credential', 'firebase_key', 'google_api', 'aws_key',
            'database_url', 'connection_string', 'jwt_token', 'bearer_token'
        ]
        
        # Common false positive patterns to exclude
        false_positive_patterns = [
            'api_version', 'api_level', 'api_name', 'api_description',
            'secret_key_algorithm', 'password_hash', 'token_type',
            'auth_provider', 'login_activity', 'private_mode',
            'config_version', 'server_name', 'database_name',
            'url_scheme', 'endpoint_url', 'firebase_project',
            'google_play', 'amazon_app', 'aws_region'
        ]
        
        content_lower = content.lower()
        
        # Check for sensitive keywords
        has_sensitive = any(keyword in content_lower for keyword in sensitive_keywords)
        
        # Exclude false positives
        has_false_positive = any(pattern in content_lower for pattern in false_positive_patterns)
        
        # Additional context checks
        # If content is very short or looks like configuration, be more lenient
        if len(content) < 100:
            return False
        
        # If it looks like a standard Android resource file, be more careful
        if any(indicator in content_lower for indicator in ['android:', 'res/', 'values/', 'strings.xml']):
            return has_sensitive and not has_false_positive
        
        return has_sensitive and not has_false_positive
    
    def _is_interesting_base64(self, decoded_data):
        """Check if decoded Base64 data is interesting (not just random bytes)"""
        try:
            # Check if it's text
            text = decoded_data.decode('utf-8', errors='ignore')
            
            # Skip if it's just random characters
            if len(text) < 10:
                return False
            
            # Check if it contains meaningful content
            meaningful_indicators = [
                'http', 'https', 'api', 'key', 'token', 'secret',
                'password', 'user', 'admin', 'config', 'database',
                'json', 'xml', 'html', 'javascript', 'python'
            ]
            
            text_lower = text.lower()
            if any(indicator in text_lower for indicator in meaningful_indicators):
                return True
            
            # Check if it's mostly readable text
            readable_chars = sum(1 for c in text if c.isprintable() or c.isspace())
            if readable_chars / len(text) > 0.8:
                return True
                
            return False
            
        except Exception:
            return False
    
    def _is_printable(self, data):
        """Check if binary data is printable text"""
        try:
            text = data.decode('utf-8')
            return all(c.isprintable() or c.isspace() for c in text)
        except:
            return False