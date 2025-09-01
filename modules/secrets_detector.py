#!/usr/bin/env python3
"""
Secrets Detector
Advanced detection of hardcoded secrets and sensitive information
"""

import re
import json
import base64
from pathlib import Path

class SecretsDetector:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
        # Comprehensive secret patterns with improved detection
        self.secret_patterns = [
            # Generic API patterns (reduced minimum length for better detection)
            (r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'API Key'),
            (r'["\']?(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Secret Key'),
            (r'["\']?(?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Access Token'),
            (r'["\']?(?:auth[_-]?token|authtoken)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Auth Token'),
            (r'["\']?(?:private[_-]?key|privatekey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Private Key'),
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password'),
            
            # Additional patterns for better detection
            (r'["\']?(?:client[_-]?secret|clientsecret)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Client Secret'),
            (r'["\']?(?:session[_-]?key|sessionkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Session Key'),
            (r'["\']?(?:encryption[_-]?key|encryptionkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Encryption Key'),
            (r'["\']?(?:decryption[_-]?key|decryptionkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Decryption Key'),
            (r'["\']?(?:master[_-]?key|masterkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Master Key'),
            (r'["\']?(?:root[_-]?key|rootkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Root Key'),
            (r'["\']?(?:admin[_-]?key|adminkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Admin Key'),
            (r'["\']?(?:user[_-]?key|userkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'User Key'),
            (r'["\']?(?:app[_-]?key|appkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'App Key'),
            (r'["\']?(?:service[_-]?key|servicekey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Service Key'),
            (r'["\']?(?:database[_-]?key|databasekey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Database Key'),
            (r'["\']?(?:server[_-]?key|serverkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Server Key'),
            (r'["\']?(?:config[_-]?key|configkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Config Key'),
            (r'["\']?(?:env[_-]?key|envkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Environment Key'),
            (r'["\']?(?:prod[_-]?key|prodkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Production Key'),
            (r'["\']?(?:dev[_-]?key|devkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Development Key'),
            (r'["\']?(?:test[_-]?key|testkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Test Key'),
            (r'["\']?(?:staging[_-]?key|stagingkey)["\']?\s*[:=]\s*["\']([^"\']{15,})["\']', 'Staging Key'),
            
            # Cloud service specific (high confidence patterns)
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'ya29\.[0-9A-Za-z\-_]{20,}', 'Google OAuth Access Token'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Secret Key'),
            (r'rk_live_[0-9a-zA-Z]{24}', 'Stripe Restricted Key'),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Publishable Key'),
            (r'pk_test_[0-9a-zA-Z]{24}', 'Stripe Test Publishable Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'[0-9a-zA-Z/+]{40}', 'AWS Secret Access Key'),
            
            # Firebase (more specific patterns)
            (r'https://[a-zA-Z0-9-]+\.firebaseio\.com', 'Firebase Database URL'),
            (r'[0-9]+-[0-9a-zA-Z_-]+\.apps\.googleusercontent\.com', 'Firebase Client ID'),
            
            # Social media & messaging (specific patterns)
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),
            (r'[0-9]{13,19}:[0-9a-zA-Z_-]{35}', 'Telegram Bot Token'),
            (r'[0-9]+:[a-zA-Z0-9_-]{35}', 'Discord Bot Token'),
            
            # Database (with stronger validation)
            (r'mongodb://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+', 'MongoDB Connection String'),
            (r'mysql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+', 'MySQL Connection String'),
            (r'postgres://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+', 'PostgreSQL Connection String'),
            
            # Generic tokens and hashes (with better context and filtering)
            (r'[0-9a-f]{32}(?![0-9a-f])', 'MD5 Hash'),
            (r'[0-9a-f]{40}(?![0-9a-f])', 'SHA1 Hash'),
            (r'[0-9a-f]{64}(?![0-9a-f])', 'SHA256 Hash'),
            (r'[A-Za-z0-9+/]{20}={0,2}', 'Base64 20-char Token'),  # Reduced minimum length
            (r'[A-Za-z0-9+/]{30}={0,2}', 'Base64 30-char Token'),
            (r'[A-Za-z0-9+/]{40}={0,2}', 'Base64 40-char Token'),
            (r'[A-Za-z0-9+/]{50}={0,2}', 'Base64 50-char Token'),
            
            # Additional hash patterns
            (r'[0-9a-f]{128}(?![0-9a-f])', 'SHA512 Hash'),
            (r'[0-9a-f]{96}(?![0-9a-f])', 'SHA384 Hash'),
            (r'[0-9a-f]{56}(?![0-9a-f])', 'SHA224 Hash'),
            
            # Token patterns without quotes (standalone tokens) - more aggressive
            (r'\b[A-Za-z0-9]{15,}\b', 'Potential Token'),
            (r'\b[0-9a-f]{15,}\b', 'Potential Hash'),
            (r'\b[A-Za-z0-9+/]{15,}={0,2}\b', 'Potential Base64 Token'),
            
            # JWT tokens (more specific with minimum length)
            (r'eyJ[A-Za-z0-9_/+\-]{20,}\.eyJ[A-Za-z0-9_/+\-]{20,}\.[A-Za-z0-9_/+\-]{20,}', 'JWT Token'),
            
            # URLs with credentials (more specific)
            (r'https?://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+', 'URL with Credentials'),
            
            # Encryption keys (PEM format)
            (r'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----', 'PEM Key'),
        ]
        
        # File extensions to search
        self.searchable_extensions = [
            '.xml', '.json', '.txt', '.properties', '.java', '.js', '.jsx',
            '.ts', '.tsx', '.dart', '.kt', '.swift', '.py', '.php', '.rb',
            '.go', '.rs', '.cpp', '.c', '.h', '.hpp', '.cs', '.vb', '.sql',
            '.yml', '.yaml', '.toml', '.ini', '.conf', '.cfg', '.env',
            '.gradle', '.pro', '.mk', '.cmake', '.sh', '.bat', '.ps1',
            '.md', '.rst', '.tex', '.html', '.htm', '.css', '.scss',
            '.less', '.sass', '.styl', '.coffee', '.clj', '.scala',
            '.hs', '.ml', '.fs', '.erl', '.ex', '.pl', '.pm', '.t',
            '.lua', '.r', '.m', '.mm', '.f', '.f90', '.f95', '.f03',
            '.pas', '.d', '.nim', '.zig', '.v', '.sv', '.vhd', '.vhdl'
        ]
        
    def analyze(self):
        """Detect hardcoded secrets"""
        results = {
            "hardcoded_secrets": [],
            "firebase_configs": [],
            "google_services": [],
            "encrypted_data": [],
            "suspicious_base64": [],
            "urls_with_secrets": [],
            "config_files": [],
            "statistics": {
                "files_scanned": 0,
                "secrets_found": 0,
                "high_risk_secrets": 0
            },
            "errors": []
        }
        
        try:
            # Get all searchable files
            searchable_files = self._get_searchable_files()
            results["statistics"]["files_scanned"] = len(searchable_files)
            
            # Search for secrets in each file
            for file_path in searchable_files:
                try:
                    content = self._read_file_safely(file_path)
                    if content:
                        file_secrets = self._search_file_for_secrets(file_path, content)
                        results["hardcoded_secrets"].extend(file_secrets)
                        
                        # Special analysis for specific file types
                        if file_path.name == 'google-services.json':
                            results["google_services"].append(self._analyze_google_services(file_path, content))
                        elif 'firebase' in file_path.name.lower():
                            results["firebase_configs"].append(self._analyze_firebase_config(file_path, content))
                            
                except Exception as e:
                    results["errors"].append(f"Error analyzing {file_path}: {str(e)}")
            
            # Additional analysis
            results["encrypted_data"] = self._find_encrypted_data()
            results["suspicious_base64"] = self._find_suspicious_base64()
            results["urls_with_secrets"] = self._find_urls_with_secrets()
            results["config_files"] = self._analyze_config_files()
            
            # Update statistics
            results["statistics"]["secrets_found"] = len(results["hardcoded_secrets"])
            results["statistics"]["high_risk_secrets"] = len([
                s for s in results["hardcoded_secrets"] 
                if s.get("risk_level") == "high"
            ])
            
        except Exception as e:
            results["errors"].append(f"Secrets detection error: {str(e)}")
            
        return results
    
    def _get_searchable_files(self):
        """Get list of files to search for secrets"""
        files = []
        
        for ext in self.searchable_extensions:
            files.extend(self.extract_dir.rglob(f"*{ext}"))
        
        # Filter files by size and type
        filtered_files = []
        for f in files:
            try:
                # Skip very large files
                if f.stat().st_size > 1000000:  # 1MB limit
                    continue
                
                # Skip binary files
                if self._is_binary_file(f):
                    continue
                
                # Skip resource files that are likely binary
                if any(binary_pattern in str(f) for binary_pattern in [
                    'resources.arsc', '.so', '.dex', '.apk', '.jar', '.aar',
                    'META-INF', 'AndroidManifest.xml'  # Skip binary manifest
                ]):
                    continue
                
                filtered_files.append(f)
            except Exception:
                continue
        
        return filtered_files
    
    def _is_binary_file(self, file_path):
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes (common in binary files)
                if b'\x00' in chunk:
                    return True
                
                # Check if mostly printable
                printable_count = sum(1 for byte in chunk if 32 <= byte <= 126 or byte in [9, 10, 13])
                if printable_count / len(chunk) < 0.8:
                    return True
                    
        except Exception:
            return True
        
        return False
    
    def _search_file_for_secrets(self, file_path, content):
        """Search for secrets in file content"""
        secrets = []
        
        for pattern, secret_type in self.secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                secret_value = match.group(1) if match.groups() else match.group(0)
                
                # Skip obvious false positives
                if self._is_false_positive(secret_value, secret_type):
                    continue
                
                # Determine risk level
                risk_level = self._assess_risk_level(secret_type, secret_value)
                
                secret_info = {
                    "type": secret_type,
                    "value": self._mask_secret(secret_value),
                    "full_value_hash": hash(secret_value),  # For deduplication
                    "file": str(file_path.relative_to(self.extract_dir)),
                    "line_number": content[:match.start()].count('\n') + 1,
                    "context": self._get_context(content, match.start(), match.end()),
                    "risk_level": risk_level,
                    "length": len(secret_value)
                }
                
                secrets.append(secret_info)
        
        return secrets
    
    def _is_false_positive(self, value, secret_type):
        """Check if detected secret is likely a false positive"""
        # Enhanced false positive patterns
        false_positive_patterns = [
            # Common placeholders
            'example', 'test', 'demo', 'sample', 'placeholder', 'dummy',
            'your_key_here', 'insert_key_here', 'replace_with', 'todo',
            'null', 'none', 'empty', '123456', 'password', 'secret',
            'fake', 'mock', 'stub', 'temp', 'temporary', 'dummy_key',
            'api_key_here', 'secret_here', 'token_here', 'key_here',
            'your_api_key', 'your_secret', 'your_token', 'your_password',
            'add_your_key', 'add_your_secret', 'add_your_token',
            'replace_with_your', 'insert_your', 'enter_your',
            'config_key', 'config_secret', 'config_token',
            'default_key', 'default_secret', 'default_token',
            'sample_key', 'sample_secret', 'sample_token',
            'test_key', 'test_secret', 'test_token',
            'dev_key', 'dev_secret', 'dev_token',
            'staging_key', 'staging_secret', 'staging_token'
        ]
        
        # File-specific false positives
        file_specific_false_positives = {
            'strings.xml': ['app_name', 'app_label', 'app_description'],
            'build.gradle': ['applicationId', 'versionName', 'versionCode'],
            'AndroidManifest.xml': ['package', 'android:label', 'android:description'],
            'gradle.properties': ['org.gradle', 'android.useAndroidX', 'android.enableJetifier']
        }
        
        value_lower = value.lower()
        
        # Check for obvious placeholders
        if any(fp in value_lower for fp in false_positive_patterns):
            return True
        
        # Check for repeated characters (likely placeholder)
        if len(set(value)) <= 3 and len(value) > 5:
            return True
        
        # Check for sequential patterns (like abcdef -> 012345)
        try:
            if value.lower() == value.lower().translate(str.maketrans('abcdefghijklmnopqrstuvwxyz', '0123456789'*26)):
                return True
        except ValueError:
            pass  # Skip if maketrans fails
        
        # Check for all same characters
        if len(set(value)) == 1 and len(value) > 3:
            return True
        
        # Check for obvious test patterns
        test_patterns = [
            r'^test.*$', r'^demo.*$', r'^sample.*$', r'^example.*$',
            r'^fake.*$', r'^mock.*$', r'^dummy.*$', r'^temp.*$',
            r'^placeholder.*$', r'^your_.*$', r'^insert_.*$',
            r'^replace_.*$', r'^add_.*$', r'^enter_.*$'
        ]
        
        for pattern in test_patterns:
            if re.match(pattern, value_lower):
                return True
        
        # Check for too short values (likely not real secrets)
        if len(value) < 5:  # Reduced minimum length for better detection
            return True
        
        # Check for common words that are not secrets
        common_words = [
            'api', 'key', 'secret', 'token', 'password', 'auth',
            'login', 'user', 'admin', 'root', 'guest', 'public',
            'private', 'internal', 'external', 'local', 'remote',
            'server', 'client', 'database', 'db', 'url', 'uri',
            'http', 'https', 'ftp', 'smtp', 'pop3', 'imap'
        ]
        
        if value_lower in common_words:
            return True
        
        # Check for obvious non-secret patterns (reduced filtering)
        if re.match(r'^[a-zA-Z]+$', value) and len(value) < 5:
            return True  # Very short simple words are likely not secrets
        
        if re.match(r'^[0-9]+$', value) and len(value) < 5:
            return True  # Very short simple numbers are likely not secrets
        
        # Check for common Android resource patterns (reduced filtering)
        if re.match(r'^[a-z_]+$', value) and len(value) < 8:
            return True  # Very short Android resource names are not secrets
        
        # Check for common file extensions (reduced filtering)
        if re.match(r'^[a-zA-Z0-9._-]+\.(xml|json|txt|properties|java|js|ts|dart|kt|swift|py|php|rb|go|rs|cpp|c|h|hpp|cs|vb|sql|yml|yaml|toml|ini|conf|cfg|env)$', value) and len(value) < 10:
            return True  # Short file names are not secrets
        
        return False
    
    def _assess_risk_level(self, secret_type, value):
        """Assess risk level of detected secret"""
        high_risk_types = [
            'AWS Access Key ID', 'AWS Secret Access Key', 'Private Key',
            'Stripe Live Secret Key', 'Firebase Database URL', 'JWT Token'
        ]
        
        medium_risk_types = [
            'API Key', 'Secret Key', 'Access Token', 'Auth Token',
            'Google API Key', 'Stripe Test Secret Key'
        ]
        
        if secret_type in high_risk_types:
            return "high"
        elif secret_type in medium_risk_types:
            return "medium"
        elif len(value) > 20:
            return "medium"
        else:
            return "low"
    
    def _mask_secret(self, value):
        """Mask secret value for display"""
        # Return the full value instead of masking
        return value
    
    def _get_context(self, content, start, end):
        """Get context around the secret"""
        lines = content.split('\n')
        char_to_line = {}
        char_count = 0
        
        for i, line in enumerate(lines):
            for j in range(len(line) + 1):  # +1 for newline
                char_to_line[char_count] = i
                char_count += 1
        
        start_line = char_to_line.get(start, 0)
        end_line = char_to_line.get(end, start_line)
        
        # Get surrounding lines
        context_start = max(0, start_line - 1)
        context_end = min(len(lines), end_line + 2)
        
        return '\n'.join(lines[context_start:context_end])
    
    def _analyze_google_services(self, file_path, content):
        """Analyze google-services.json file"""
        try:
            data = json.loads(content)
            
            return {
                "file": str(file_path.relative_to(self.extract_dir)),
                "project_id": data.get("project_info", {}).get("project_id"),
                "project_number": data.get("project_info", {}).get("project_number"),
                "firebase_url": data.get("project_info", {}).get("firebase_url"),
                "api_keys": [client.get("api_key", {}).get("current_key") 
                           for client in data.get("client", [])],
                "oauth_client_ids": [client.get("client_id") 
                                   for oauth in data.get("client", [])
                                   for client in oauth.get("oauth_client", [])]
            }
        except:
            return {"file": str(file_path.relative_to(self.extract_dir)), "error": "Parse error"}
    
    def _analyze_firebase_config(self, file_path, content):
        """Analyze Firebase configuration files"""
        firebase_patterns = [
            (r'apiKey["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase API Key'),
            (r'authDomain["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase Auth Domain'),
            (r'databaseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase Database URL'),
            (r'projectId["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase Project ID'),
            (r'messagingSenderId["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase Messaging Sender ID')
        ]
        
        config = {"file": str(file_path.relative_to(self.extract_dir))}
        
        for pattern, key in firebase_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                config[key.lower().replace(' ', '_')] = match.group(1)
        
        return config
    
    def _find_encrypted_data(self):
        """Find potentially encrypted data"""
        encrypted_data = []
        
        # Look for files that might contain encrypted data
        for file_path in self.extract_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.enc', '.encrypted', '.aes', '.bin', '.dat']:
                encrypted_data.append({
                    "file": str(file_path.relative_to(self.extract_dir)),
                    "size": file_path.stat().st_size,
                    "type": "Potentially Encrypted File"
                })
        
        return encrypted_data
    
    def _find_suspicious_base64(self):
        """Find suspicious Base64 encoded data with improved filtering"""
        suspicious_b64 = []
        
        for file_path in self._get_searchable_files()[:20]:  # Limit files
            try:
                content = self._read_file_safely(file_path)
                if not content:
                    continue
                
                # Look for long Base64 strings (increased minimum length)
                b64_pattern = r'[A-Za-z0-9+/]{60,}={0,2}'  # Increased from 40 to 60
                matches = re.finditer(b64_pattern, content)
                
                for match in matches:
                    b64_str = match.group(0)
                    try:
                        decoded = base64.b64decode(b64_str + "===")
                        if len(decoded) > 20 and self._is_printable_text(decoded[:100]):
                            suspicious_b64.append({
                                "file": str(file_path.relative_to(self.extract_dir)),
                                "encoded_length": len(b64_str),
                                "decoded_preview": decoded[:100].decode('utf-8', errors='ignore'),
                                "line_number": content[:match.start()].count('\n') + 1
                            })
                    except:
                        continue
                        
            except Exception:
                continue
        
        return suspicious_b64[:10]  # Limit results
    
    def _find_urls_with_secrets(self):
        """Find URLs that might contain secrets"""
        urls_with_secrets = []
        
        url_pattern = r'https?://[^\s"\'<>]+'
        
        for file_path in self._get_searchable_files()[:30]:
            try:
                content = self._read_file_safely(file_path)
                if not content:
                    continue
                
                urls = re.findall(url_pattern, content, re.IGNORECASE)
                
                for url in urls:
                    # Check if URL contains potential secrets with better filtering
                    secret_keywords = ['api_key', 'access_token', 'secret_key', 'auth_token', 'private_key']
                    if any(keyword in url.lower() for keyword in secret_keywords):
                        # Additional validation to avoid false positives
                        if len(url) > 50 and not any(fp in url.lower() for fp in ['example.com', 'localhost', '127.0.0.1', 'test.com']):
                            urls_with_secrets.append({
                                "url": url,
                                "file": str(file_path.relative_to(self.extract_dir)),
                                "risk": "potential_secret_in_url"
                            })
                        
            except Exception:
                continue
        
        return urls_with_secrets[:20]
    
    def _analyze_config_files(self):
        """Analyze configuration files for sensitive data"""
        config_files = []
        
        config_patterns = ["*.properties", "*.conf", "*.cfg", "*.ini", "*.env"]
        
        for pattern in config_patterns:
            for config_file in self.extract_dir.rglob(pattern):
                try:
                    content = self._read_file_safely(config_file)
                    if content and self._contains_sensitive_config(content):
                        config_files.append({
                            "file": str(config_file.relative_to(self.extract_dir)),
                            "size": config_file.stat().st_size,
                            "sensitive_keys": self._extract_sensitive_keys(content)
                        })
                except Exception:
                    continue
        
        return config_files[:10]
    
    def _contains_sensitive_config(self, content):
        """Check if configuration contains sensitive data"""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api', 'auth',
            'database', 'db', 'server', 'host', 'endpoint'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in sensitive_keywords)
    
    def _extract_sensitive_keys(self, content):
        """Extract sensitive configuration keys"""
        sensitive_keys = []
        
        # Look for key=value patterns
        key_pattern = r'^([^=\n]+)=([^\n]+)$'
        matches = re.findall(key_pattern, content, re.MULTILINE)
        
        for key, value in matches:
            key = key.strip()
            if any(keyword in key.lower() for keyword in ['password', 'secret', 'key', 'token', 'api']):
                sensitive_keys.append(key)
        
        return sensitive_keys
    
    def _read_file_safely(self, file_path):
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
    
    def _is_printable_text(self, data):
        """Check if binary data is printable text"""
        try:
            text = data.decode('utf-8')
            return all(c.isprintable() or c.isspace() for c in text)
        except:
            return False