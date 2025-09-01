#!/usr/bin/env python3
"""
DEX File Analyzer
Analyzes Android DEX files and extracts code information
"""

import os
import re
import subprocess
from pathlib import Path

class DEXAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze DEX files"""
        results = {
            "dex_files": [],
            "total_classes": 0,
            "total_methods": 0,
            "packages": [],
            "classes": [],
            "methods": [],
            "hardcoded_strings": [],
            "urls": [],
            "api_keys": [],
            "reflection_usage": [],
            "dynamic_loading": [],
            "crypto_usage": [],
            "flutter_detected": False,
            "obfuscation_detected": False,
            "errors": []
        }
        
        try:
            # Find all DEX files
            dex_files = list(self.extract_dir.glob("*.dex"))
            
            for dex_file in dex_files:
                dex_info = self._analyze_dex_file(dex_file)
                results["dex_files"].append(dex_info)
                
                # Aggregate data
                results["total_classes"] += dex_info.get("class_count", 0)
                results["total_methods"] += dex_info.get("method_count", 0)
                
                # Collect unique packages
                for pkg in dex_info.get("packages", []):
                    if pkg not in results["packages"]:
                        results["packages"].append(pkg)
            
            # Analyze decompiled code if possible
            self._analyze_decompiled_code(results)
            
            # Detect obfuscation
            results["obfuscation_detected"] = self._detect_obfuscation(results)
            
            # Check for Flutter
            results["flutter_detected"] = self._detect_flutter()
            
        except Exception as e:
            results["errors"].append(f"DEX analysis error: {str(e)}")
            
        return results
    
    def _analyze_dex_file(self, dex_file):
        """Analyze individual DEX file"""
        dex_info = {
            "filename": dex_file.name,
            "size": dex_file.stat().st_size,
            "class_count": 0,
            "method_count": 0,
            "packages": [],
            "classes": [],
            "strings": []
        }
        
        try:
            # Use dexdump to analyze DEX file
            result = subprocess.run(['dexdump', '-l', 'plain', str(dex_file)], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self._parse_dexdump_output(result.stdout, dex_info)
            else:
                # Try alternative tools
                self._try_alternative_dex_analysis(dex_file, dex_info)
                
        except subprocess.TimeoutExpired:
            dex_info["errors"] = ["Dexdump timeout"]
        except FileNotFoundError:
            # dexdump not available, try alternatives
            self._try_alternative_dex_analysis(dex_file, dex_info)
        except Exception as e:
            dex_info["errors"] = [f"DEX analysis error: {str(e)}"]
            
        return dex_info
    
    def _parse_dexdump_output(self, output, dex_info):
        """Parse dexdump output"""
        lines = output.split('\n')
        current_class = None
        
        for line in lines:
            line = line.strip()
            
            # Class definitions
            if line.startswith('Class #'):
                class_match = re.search(r"Class #\d+.*descriptor: '([^']+)'", line)
                if class_match:
                    class_name = class_match.group(1)
                    current_class = class_name
                    dex_info["classes"].append(class_name)
                    dex_info["class_count"] += 1
                    
                    # Extract package name
                    if '/' in class_name:
                        package = '/'.join(class_name.split('/')[:-1])
                        if package not in dex_info["packages"]:
                            dex_info["packages"].append(package)
            
            # Method definitions
            elif line.startswith('Direct methods:') or line.startswith('Virtual methods:'):
                continue
            elif current_class and ('method' in line.lower() or 'constructor' in line.lower()):
                dex_info["method_count"] += 1
            
            # String constants
            elif line.startswith('string_data_item'):
                string_match = re.search(r'"([^"]*)"', line)
                if string_match:
                    string_val = string_match.group(1)
                    dex_info["strings"].append(string_val)
    
    def _try_alternative_dex_analysis(self, dex_file, dex_info):
        """Try alternative DEX analysis methods"""
        try:
            # Try using d2j-dex2jar if available
            jar_output = self.extract_dir / f"{dex_file.stem}.jar"
            result = subprocess.run(['d2j-dex2jar', str(dex_file), '-o', str(jar_output)], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and jar_output.exists():
                # Analyze the JAR file
                self._analyze_jar_file(jar_output, dex_info)
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    def _analyze_jar_file(self, jar_file, dex_info):
        """Analyze converted JAR file"""
        try:
            import zipfile
            with zipfile.ZipFile(jar_file, 'r') as jar:
                for file_path in jar.namelist():
                    if file_path.endswith('.class'):
                        class_name = file_path.replace('/', '.').replace('.class', '')
                        dex_info["classes"].append(class_name)
                        dex_info["class_count"] += 1
                        
                        # Extract package
                        if '.' in class_name:
                            package = '.'.join(class_name.split('.')[:-1])
                            if package not in dex_info["packages"]:
                                dex_info["packages"].append(package)
        except Exception:
            pass
    
    def _analyze_decompiled_code(self, results):
        """Analyze decompiled code for security issues"""
        try:
            # Look for decompiled source code
            java_files = list(self.extract_dir.rglob("*.java"))
            smali_files = list(self.extract_dir.rglob("*.smali"))
            
            all_files = java_files + smali_files
            
            for source_file in all_files[:50]:  # Limit to prevent excessive processing
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self._extract_security_patterns(content, results)
                except Exception:
                    continue
                    
        except Exception as e:
            results["errors"].append(f"Decompiled code analysis error: {str(e)}")
    
    def _extract_security_patterns(self, content, results):
        """Extract security-relevant patterns from code with improved filtering"""
        # URL patterns (more specific)
        url_pattern = re.compile(r'https?://[^\s"\'<>]{10,}', re.IGNORECASE)
        urls = url_pattern.findall(content)
        for url in urls:
            # Filter out common false positives
            if not any(fp in url.lower() for fp in ['example.com', 'localhost', '127.0.0.1', 'test.com']):
                if url not in results["urls"]:
                    results["urls"].append(url)
        
        # API key patterns with better validation
        api_patterns = [
            (r'["\'](?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'API Key'),
            (r'["\'](?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Access Token'),
            (r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Secret Key'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Key'),
        ]
        
        for pattern, key_type in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                
                # Validate the match
                if match and self._is_valid_api_key(match, key_type):
                    results["api_keys"].append(match)
        
        # Reflection usage (more specific patterns)
        reflection_patterns = [
            (r'Class\.forName\s*\(\s*["\'][^"\']+["\']', 'Class.forName with string'),
            (r'getDeclaredMethod\s*\(\s*["\'][^"\']+["\']', 'getDeclaredMethod with string'),
            (r'getMethod\s*\(\s*["\'][^"\']+["\']', 'getMethod with string'),
            (r'newInstance\s*\(\s*\)', 'newInstance call'),
            (r'invoke\s*\(\s*[^)]+\)', 'invoke call')
        ]
        
        for pattern, description in reflection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if it's not in a comment or string
                if not self._is_in_comment_or_string(content, pattern):
                    results["reflection_usage"].append(description)
        
        # Dynamic code loading (more specific)
        dynamic_patterns = [
            (r'DexClassLoader\s*\(', 'DexClassLoader usage'),
            (r'PathClassLoader\s*\(', 'PathClassLoader usage'),
            (r'URLClassLoader\s*\(', 'URLClassLoader usage'),
            (r'loadClass\s*\(\s*["\'][^"\']+["\']', 'loadClass with string'),
            (r'defineClass\s*\(', 'defineClass usage')
        ]
        
        for pattern, description in dynamic_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not self._is_in_comment_or_string(content, pattern):
                    results["dynamic_loading"].append(description)
        
        # Cryptographic usage (more specific)
        crypto_patterns = [
            (r'Cipher\.getInstance\s*\(', 'Cipher.getInstance'),
            (r'MessageDigest\.getInstance\s*\(', 'MessageDigest.getInstance'),
            (r'KeyGenerator\.getInstance\s*\(', 'KeyGenerator.getInstance'),
            (r'SecretKeySpec\s*\(', 'SecretKeySpec usage'),
            (r'Cipher\.AES', 'AES Cipher'),
            (r'Cipher\.DES', 'DES Cipher'),
            (r'Cipher\.RSA', 'RSA Cipher'),
            (r'MessageDigest\.MD5', 'MD5 MessageDigest'),
            (r'MessageDigest\.SHA', 'SHA MessageDigest')
        ]
        
        for pattern, description in crypto_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not self._is_in_comment_or_string(content, pattern):
                    results["crypto_usage"].append(description)
    
    def _detect_obfuscation(self, results):
        """Detect code obfuscation with improved accuracy"""
        obfuscation_indicators = 0
        total_classes = len(results.get("classes", []))
        
        if total_classes == 0:
            return False
        
        # Check for short/meaningless class names (more sophisticated)
        short_names = 0
        single_char_names = 0
        
        for class_name in results.get("classes", []):
            class_short_name = class_name.split('/')[-1]
            
            # Skip common short class names that are legitimate
            legitimate_short_names = [
                'R', 'BuildConfig', 'Manifest', 'Constants', 'Utils', 'Helper',
                'Api', 'Db', 'UI', 'IO', 'Net', 'Log', 'App', 'Main', 'Test'
            ]
            
            if class_short_name in legitimate_short_names:
                continue
            
            if len(class_short_name) <= 1:
                single_char_names += 1
            elif len(class_short_name) <= 2:
                short_names += 1
        
        # More sophisticated obfuscation detection
        short_ratio = short_names / total_classes
        single_char_ratio = single_char_names / total_classes
        
        # High ratio of single-character names is a strong indicator
        if single_char_ratio > 0.1:
            obfuscation_indicators += 2
        elif short_ratio > 0.5:
            obfuscation_indicators += 1
        
        # Check for package names with single letters (but exclude common ones)
        single_char_packages = 0
        legitimate_single_char_packages = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
        
        for package in results.get("packages", []):
            parts = package.split('/')
            for part in parts:
                if len(part) == 1 and part not in legitimate_single_char_packages:
                    single_char_packages += 1
        
        if single_char_packages > 5:  # Require more evidence
            obfuscation_indicators += 1
        
        # Check for ProGuard/R8 indicators
        proguard_indicators = ['proguard', 'r8', 'obfuscation']
        for package in results.get("packages", []):
            if any(indicator in package.lower() for indicator in proguard_indicators):
                obfuscation_indicators += 1
                break
        
        return obfuscation_indicators >= 2
    
    def _is_valid_api_key(self, match, key_type):
        """Validate if a matched string is actually an API key"""
        
        # Minimum length check
        if len(match) < 10:
            return False
        
        # Skip common false positives
        false_positive_patterns = [
            'test', 'example', 'sample', 'placeholder', 'dummy',
            '123456', 'password', 'admin', 'root', 'user',
            'api_version', 'api_level', 'api_name', 'api_description'
        ]
        
        match_lower = match.lower()
        if any(fp in match_lower for fp in false_positive_patterns):
            return False
        
        # Check if it's just a simple alphanumeric string
        if match.isalnum() and len(match) < 16:
            return False
        
        # For specific key types, add additional validation
        if key_type == 'Google API Key':
            return match.startswith('AIza') and len(match) == 39
        elif key_type in ['Stripe Live Key', 'Stripe Test Key']:
            return match.startswith('sk_') and len(match) == 28
        
        return True
    
    def _is_in_comment_or_string(self, content, pattern):
        """Check if a pattern is inside a comment or string literal"""
        try:
            # Simple heuristic: check if pattern is surrounded by quotes or after //
            lines = content.split('\n')
            for line in lines:
                if '//' in line:
                    comment_start = line.find('//')
                    if re.search(pattern, line[comment_start:], re.IGNORECASE):
                        return True
                
                # Check for string literals (simplified)
                if '"' in line or "'" in line:
                    # This is a simplified check - in a real implementation,
                    # you'd need a proper parser to handle escaped quotes
                    pass
            
            return False
        except Exception:
            return False
    
    def _detect_flutter(self):
        """Detect Flutter framework"""
        # Check for Flutter-specific files
        flutter_indicators = [
            "libflutter.so",
            "libapp.so",
            "kernel_blob.bin",
            "isolate_snapshot_data",
            "vm_snapshot_data"
        ]
        
        for indicator in flutter_indicators:
            if (self.extract_dir / indicator).exists():
                return True
            
            # Check in lib directories
            for lib_dir in self.extract_dir.glob("lib/*/"):
                if (lib_dir / indicator).exists():
                    return True
        
        return False