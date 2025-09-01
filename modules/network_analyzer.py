#!/usr/bin/env python3
"""
Network Security Analyzer
Analyzes network security configurations and potential vulnerabilities
"""

import re
import json
from pathlib import Path
import os

class NetworkAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze network security configurations"""
        results = {
            "network_security_config": {},
            "cleartext_traffic": {},
            "domain_verification": {},
            "certificate_pinning": {},
            "network_permissions": [],
            "url_patterns": [],
            "api_endpoints": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
        try:
            # Analyze network security config
            results["network_security_config"] = self._analyze_network_security_config()
            
            # Check for cleartext traffic
            results["cleartext_traffic"] = self._analyze_cleartext_traffic()
            
            # Check domain verification
            results["domain_verification"] = self._analyze_domain_verification()
            
            # Check certificate pinning
            results["certificate_pinning"] = self._analyze_certificate_pinning()
            
            # Extract network permissions
            results["network_permissions"] = self._extract_network_permissions()
            
            # Extract URL patterns and API endpoints
            results["url_patterns"] = self._extract_url_patterns()
            results["api_endpoints"] = self._extract_api_endpoints()
            
            # Check for vulnerabilities
            results["vulnerabilities"] = self._check_network_vulnerabilities(results)
            
            # Generate recommendations
            results["recommendations"] = self._generate_network_recommendations(results)
            
        except Exception as e:
            results["vulnerabilities"].append(f"Network analysis error: {str(e)}")
            
        return results
    
    def _analyze_network_security_config(self):
        """Analyze network security configuration"""
        config_info = {
            "config_file_exists": False,
            "config_path": "",
            "cleartext_traffic_allowed": False,
            "domain_configs": [],
            "trust_anchors": [],
            "certificate_pinning": False
        }
        
        # Look for network security config file
        config_paths = [
            "res/xml/network_security_config.xml",
            "res/values/network_security_config.xml"
        ]
        
        for config_path in config_paths:
            full_path = self.extract_dir / config_path
            if full_path.exists():
                config_info["config_file_exists"] = True
                config_info["config_path"] = config_path
                config_info.update(self._parse_network_security_config(full_path))
                break
        
        return config_info
    
    def _parse_network_security_config(self, config_file):
        """Parse network security configuration XML"""
        config_data = {
            "cleartext_traffic_allowed": False,
            "domain_configs": [],
            "trust_anchors": []
        }
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for cleartext traffic
            if 'cleartextTrafficPermitted="true"' in content:
                config_data["cleartext_traffic_allowed"] = True
            
            # Extract domain configurations
            domain_pattern = r'<domain-config[^>]*>(.*?)</domain-config>'
            domain_matches = re.findall(domain_pattern, content, re.DOTALL)
            
            for domain_match in domain_matches:
                domain_config = self._parse_domain_config(domain_match)
                config_data["domain_configs"].append(domain_config)
            
            # Extract trust anchors
            trust_pattern = r'<trust-anchors>(.*?)</trust-anchors>'
            trust_matches = re.findall(trust_pattern, content, re.DOTALL)
            
            for trust_match in trust_matches:
                trust_config = self._parse_trust_anchors(trust_match)
                config_data["trust_anchors"].append(trust_config)
                
        except Exception as e:
            config_data["error"] = str(e)
            
        return config_data
    
    def _parse_domain_config(self, domain_content):
        """Parse domain configuration"""
        config = {
            "domain": "",
            "cleartext_traffic": False,
            "certificate_pinning": False,
            "trust_anchors": []
        }
        
        # Extract domain
        domain_match = re.search(r'domain="([^"]*)"', domain_content)
        if domain_match:
            config["domain"] = domain_match.group(1)
        
        # Check cleartext traffic
        if 'cleartextTrafficPermitted="true"' in domain_content:
            config["cleartext_traffic"] = True
        
        # Check certificate pinning
        if '<pin-set>' in domain_content:
            config["certificate_pinning"] = True
        
        return config
    
    def _parse_trust_anchors(self, trust_content):
        """Parse trust anchors configuration"""
        trust_config = {
            "system_certs": False,
            "user_certs": False,
            "custom_certs": []
        }
        
        if '<certificates src="system"/>' in trust_content:
            trust_config["system_certs"] = True
        
        if '<certificates src="user"/>' in trust_content:
            trust_config["user_certs"] = True
        
        # Extract custom certificates
        cert_pattern = r'<certificates src="@raw/([^"]*)"'
        cert_matches = re.findall(cert_pattern, trust_content)
        trust_config["custom_certs"] = cert_matches
        
        return trust_config
    
    def _analyze_cleartext_traffic(self):
        """Analyze cleartext traffic settings"""
        cleartext_info = {
            "manifest_allows_cleartext": False,
            "network_config_allows_cleartext": False,
            "http_urls_found": [],
            "vulnerable_domains": []
        }
        
        # Check manifest for cleartext traffic
        manifest_path = self.extract_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_content = f.read()
                
            if 'android:usesCleartextTraffic="true"' in manifest_content:
                cleartext_info["manifest_allows_cleartext"] = True
        
        # Check network security config
        config_paths = [
            "res/xml/network_security_config.xml",
            "res/values/network_security_config.xml"
        ]
        
        for config_path in config_paths:
            full_path = self.extract_dir / config_path
            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8') as f:
                    config_content = f.read()
                    
                if 'cleartextTrafficPermitted="true"' in config_content:
                    cleartext_info["network_config_allows_cleartext"] = True
        
        # Search for HTTP URLs in code
        cleartext_info["http_urls_found"] = self._find_http_urls()
        
        return cleartext_info
    
    def _find_http_urls(self):
        """Find HTTP URLs in the codebase"""
        http_urls = []
        
        # Search in DEX files and other text files
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Find HTTP URLs
                        http_pattern = r'https?://[^\s"\'<>]+'
                        matches = re.findall(http_pattern, content)
                        http_urls.extend(matches)
                        
                    except Exception:
                        continue
        
        return list(set(http_urls))  # Remove duplicates
    
    def _analyze_domain_verification(self):
        """Analyze domain verification settings"""
        domain_info = {
            "auto_verify_domains": [],
            "verification_intent_filters": [],
            "assetlinks_found": False
        }
        
        # Check manifest for auto-verify domains
        manifest_path = self.extract_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_content = f.read()
                
            # Find auto-verify domains
            auto_verify_pattern = r'android:autoVerify="true"[^>]*android:host="([^"]*)"'
            matches = re.findall(auto_verify_pattern, manifest_content)
            domain_info["auto_verify_domains"] = matches
        
        # Check for assetlinks.json
        assetlinks_path = self.extract_dir / "assets" / ".well-known" / "assetlinks.json"
        if assetlinks_path.exists():
            domain_info["assetlinks_found"] = True
        
        return domain_info
    
    def _analyze_certificate_pinning(self):
        """Analyze certificate pinning implementation"""
        pinning_info = {
            "pinning_implemented": False,
            "pinning_libraries": [],
            "custom_pinning": False,
            "pinning_methods": []
        }
        
        # Check for common pinning libraries
        pinning_libraries = [
            "okhttp3.CertificatePinner",
            "com.android.volley.toolbox.HurlStack",
            "org.conscrypt.ConscryptHostnameVerifier"
        ]
        
        # Search in DEX files
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for library in pinning_libraries:
                            if library in content:
                                pinning_info["pinning_libraries"].append(library)
                                pinning_info["pinning_implemented"] = True
                                
                    except Exception:
                        continue
        
        # Check for custom pinning implementations
        pinning_patterns = [
            r'X509TrustManager',
            r'SSLSocketFactory',
            r'HostnameVerifier'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern in pinning_patterns:
                            if re.search(pattern, content):
                                pinning_info["custom_pinning"] = True
                                pinning_info["pinning_methods"].append(pattern)
                                
                    except Exception:
                        continue
        
        return pinning_info
    
    def _extract_network_permissions(self):
        """Extract network-related permissions"""
        network_permissions = []
        
        manifest_path = self.extract_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_content = f.read()
                
            # Network-related permissions
            network_perms = [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.CHANGE_WIFI_STATE",
                "android.permission.CHANGE_NETWORK_STATE"
            ]
            
            for perm in network_perms:
                if perm in manifest_content:
                    network_permissions.append(perm)
        
        return network_permissions
    
    def _extract_url_patterns(self):
        """Extract URL patterns from the codebase"""
        url_patterns = []
        
        # Common URL patterns
        patterns = [
            r'https?://[^\s"\'<>]+',
            r'ws://[^\s"\'<>]+',
            r'wss://[^\s"\'<>]+'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern in patterns:
                            matches = re.findall(pattern, content)
                            url_patterns.extend(matches)
                            
                    except Exception:
                        continue
        
        return list(set(url_patterns))  # Remove duplicates
    
    def _extract_api_endpoints(self):
        """Extract API endpoints from the codebase"""
        api_endpoints = []
        
        # Common API endpoint patterns
        api_patterns = [
            r'https?://[^/]+/api/[^\s"\'<>]+',
            r'https?://[^/]+/v\d+/[^\s"\'<>]+',
            r'https?://[^/]+/rest/[^\s"\'<>]+'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern in api_patterns:
                            matches = re.findall(pattern, content)
                            api_endpoints.extend(matches)
                            
                    except Exception:
                        continue
        
        return list(set(api_endpoints))  # Remove duplicates
    
    def _check_network_vulnerabilities(self, results):
        """Check for network-related vulnerabilities"""
        vulnerabilities = []
        
        # Check for cleartext traffic
        if results["cleartext_traffic"]["manifest_allows_cleartext"]:
            vulnerabilities.append({
                "type": "CLEARTEXT_TRAFFIC_ALLOWED",
                "severity": "HIGH",
                "description": "Application allows cleartext (HTTP) traffic",
                "impact": "Sensitive data transmitted over insecure channels"
            })
        
        # Check for HTTP URLs
        if results["cleartext_traffic"]["http_urls_found"]:
            vulnerabilities.append({
                "type": "HTTP_URLS_DETECTED",
                "severity": "MEDIUM",
                "description": f"Found {len(results['cleartext_traffic']['http_urls_found'])} HTTP URLs",
                "impact": "Potential for man-in-the-middle attacks"
            })
        
        # Check for missing certificate pinning
        if not results["certificate_pinning"]["pinning_implemented"]:
            vulnerabilities.append({
                "type": "NO_CERTIFICATE_PINNING",
                "severity": "MEDIUM",
                "description": "No certificate pinning implemented",
                "impact": "Vulnerable to certificate-based attacks"
            })
        
        # Check for user certificates in trust anchors
        for trust_anchor in results["network_security_config"]["trust_anchors"]:
            if trust_anchor.get("user_certs"):
                vulnerabilities.append({
                    "type": "USER_CERTIFICATES_TRUSTED",
                    "severity": "MEDIUM",
                    "description": "Application trusts user-installed certificates",
                    "impact": "Vulnerable to certificate-based attacks"
                })
        
        return vulnerabilities
    
    def _generate_network_recommendations(self, results):
        """Generate network security recommendations"""
        recommendations = []
        
        if results["cleartext_traffic"]["manifest_allows_cleartext"]:
            recommendations.append("Disable cleartext traffic in AndroidManifest.xml")
        
        if results["cleartext_traffic"]["http_urls_found"]:
            recommendations.append("Replace all HTTP URLs with HTTPS")
        
        if not results["certificate_pinning"]["pinning_implemented"]:
            recommendations.append("Implement certificate pinning for critical domains")
        
        if not results["network_security_config"]["config_file_exists"]:
            recommendations.append("Create a network security configuration file")
        
        for trust_anchor in results["network_security_config"]["trust_anchors"]:
            if trust_anchor.get("user_certs"):
                recommendations.append("Do not trust user-installed certificates")
        
        return recommendations 