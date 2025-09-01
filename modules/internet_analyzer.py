#!/usr/bin/env python3
"""
Internet Analysis Module
Comprehensive analysis of internet-related data in APK files
Extracts hashes, URLs, emails, endpoints, and network artifacts
"""

import re
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import base64

class InternetAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Perform comprehensive internet analysis"""
        results = {
            "hashes": {
                "md5_hashes": [],
                "sha1_hashes": [],
                "sha256_hashes": [],
                "base64_strings": [],
                "other_hashes": []
            },
            "urls": {
                "http_urls": [],
                "https_urls": [],
                "websocket_urls": [],
                "ftp_urls": [],
                "other_urls": []
            },
            "emails": [],
            "endpoints": {
                "api_endpoints": [],
                "rest_endpoints": [],
                "graphql_endpoints": [],
                "soap_endpoints": [],
                "other_endpoints": []
            },
            "domains": {
                "unique_domains": [],
                "subdomains": [],
                "ip_addresses": []
            },
            "network_artifacts": {
                "api_keys": [],
                "tokens": [],
                "webhooks": [],
                "cdn_urls": [],
                "analytics_urls": []
            },
            "statistics": {
                "total_urls": 0,
                "total_emails": 0,
                "total_endpoints": 0,
                "total_domains": 0,
                "total_hashes": 0
            }
        }
        
        try:
            # Extract hashes
            results["hashes"] = self._extract_hashes()
            
            # Extract URLs
            results["urls"] = self._extract_urls()
            
            # Extract emails
            results["emails"] = self._extract_emails()
            
            # Extract endpoints
            results["endpoints"] = self._extract_endpoints()
            
            # Extract domains
            results["domains"] = self._extract_domains(results["urls"])
            
            # Extract network artifacts
            results["network_artifacts"] = self._extract_network_artifacts()
            
            # Calculate statistics
            results["statistics"] = self._calculate_statistics(results)
            
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    def _extract_hashes(self):
        """Extract various types of hashes from the codebase"""
        hashes = {
            "md5_hashes": [],
            "sha1_hashes": [],
            "sha256_hashes": [],
            "base64_strings": [],
            "other_hashes": []
        }
        
        # Hash patterns
        patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "base64": r'[A-Za-z0-9+/]{20,}={0,2}',
            "other": r'\b[a-fA-F0-9]{8,}\b'  # Other potential hashes
        }
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json', '.properties', '.java')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Extract MD5 hashes
                        md5_matches = re.findall(patterns["md5"], content)
                        for match in md5_matches:
                            if self._is_valid_md5(match):
                                hashes["md5_hashes"].append({
                                    "hash": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract SHA1 hashes
                        sha1_matches = re.findall(patterns["sha1"], content)
                        for match in sha1_matches:
                            if self._is_valid_sha1(match):
                                hashes["sha1_hashes"].append({
                                    "hash": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract SHA256 hashes
                        sha256_matches = re.findall(patterns["sha256"], content)
                        for match in sha256_matches:
                            if self._is_valid_sha256(match):
                                hashes["sha256_hashes"].append({
                                    "hash": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract Base64 strings
                        base64_matches = re.findall(patterns["base64"], content)
                        for match in base64_matches:
                            if self._is_valid_base64(match):
                                hashes["base64_strings"].append({
                                    "string": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match),
                                    "decoded": self._try_decode_base64(match)
                                })
                        
                    except Exception:
                        continue
        
        # Remove duplicates
        for hash_type in hashes:
            if isinstance(hashes[hash_type], list) and len(hashes[hash_type]) > 0:
                key_field = "hash" if hash_type != "base64_strings" else "string"
                hashes[hash_type] = self._remove_duplicates(hashes[hash_type], key_field)
        
        return hashes
    
    def _extract_urls(self):
        """Extract URLs from the codebase"""
        urls = {
            "http_urls": [],
            "https_urls": [],
            "websocket_urls": [],
            "ftp_urls": [],
            "other_urls": []
        }
        
        # URL patterns
        url_patterns = [
            r'https?://[^\s"\'<>]+',
            r'ws://[^\s"\'<>]+',
            r'wss://[^\s"\'<>]+',
            r'ftp://[^\s"\'<>]+',
            r'ftps://[^\s"\'<>]+'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json', '.properties', '.java', '.html', '.js')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern in url_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                url_info = self._analyze_url(match, file_path)
                                if url_info:
                                    if match.startswith('http://'):
                                        urls["http_urls"].append(url_info)
                                    elif match.startswith('https://'):
                                        urls["https_urls"].append(url_info)
                                    elif match.startswith(('ws://', 'wss://')):
                                        urls["websocket_urls"].append(url_info)
                                    elif match.startswith(('ftp://', 'ftps://')):
                                        urls["ftp_urls"].append(url_info)
                                    else:
                                        urls["other_urls"].append(url_info)
                        
                    except Exception:
                        continue
        
        # Remove duplicates
        for url_type in urls:
            urls[url_type] = self._remove_duplicates(urls[url_type], "url")
        
        return urls
    
    def _extract_emails(self):
        """Extract email addresses from the codebase"""
        emails = []
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json', '.properties', '.java', '.html')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        matches = re.findall(email_pattern, content)
                        for match in matches:
                            email_info = {
                                "email": match,
                                "file": str(file_path.relative_to(self.extract_dir)),
                                "context": self._get_context(content, match),
                                "domain": match.split('@')[1] if '@' in match else None
                            }
                            emails.append(email_info)
                        
                    except Exception:
                        continue
        
        # Remove duplicates
        emails = self._remove_duplicates(emails, "email")
        
        return emails
    
    def _extract_endpoints(self):
        """Extract API endpoints from the codebase"""
        endpoints = {
            "api_endpoints": [],
            "rest_endpoints": [],
            "graphql_endpoints": [],
            "soap_endpoints": [],
            "other_endpoints": []
        }
        
        # Endpoint patterns
        endpoint_patterns = {
            "api": [
                r'https?://[^/]+/api/[^\s"\'<>]+',
                r'https?://[^/]+/v\d+/[^\s"\'<>]+',
                r'https?://api\.[^/]+/[^\s"\'<>]+'
            ],
            "rest": [
                r'https?://[^/]+/rest/[^\s"\'<>]+',
                r'https?://[^/]+/services/[^\s"\'<>]+'
            ],
            "graphql": [
                r'https?://[^/]+/graphql[^\s"\'<>]*',
                r'https?://[^/]+/gql[^\s"\'<>]*'
            ],
            "soap": [
                r'https?://[^/]+/soap[^\s"\'<>]*',
                r'https?://[^/]+/ws[^\s"\'<>]*'
            ]
        }
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json', '.properties', '.java')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for endpoint_type, patterns in endpoint_patterns.items():
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    endpoint_info = self._analyze_endpoint(match, file_path, endpoint_type)
                                    if endpoint_info:
                                        endpoints[f"{endpoint_type}_endpoints"].append(endpoint_info)
                        
                    except Exception:
                        continue
        
        # Remove duplicates
        for endpoint_type in endpoints:
            endpoints[endpoint_type] = self._remove_duplicates(endpoints[endpoint_type], "endpoint")
        
        return endpoints
    
    def _extract_domains(self, urls):
        """Extract unique domains from URLs"""
        domains = {
            "unique_domains": [],
            "subdomains": [],
            "ip_addresses": []
        }
        
        all_urls = []
        for url_type in urls.values():
            all_urls.extend(url_type)
        
        for url_info in all_urls:
            url = url_info.get("url", "")
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                
                if domain:
                    # Check if it's an IP address
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                        if domain not in [ip["ip"] for ip in domains["ip_addresses"]]:
                            domains["ip_addresses"].append({
                                "ip": domain,
                                "urls": [url]
                            })
                    else:
                        # It's a domain
                        if domain not in [d["domain"] for d in domains["unique_domains"]]:
                            domains["unique_domains"].append({
                                "domain": domain,
                                "urls": [url],
                                "subdomain_count": domain.count('.')
                            })
                        
                        # Check for subdomains
                        if domain.count('.') > 1:
                            if domain not in [d["subdomain"] for d in domains["subdomains"]]:
                                domains["subdomains"].append({
                                    "subdomain": domain,
                                    "parent_domain": '.'.join(domain.split('.')[-2:]),
                                    "urls": [url]
                                })
            except Exception:
                continue
        
        return domains
    
    def _extract_network_artifacts(self):
        """Extract network-related artifacts"""
        artifacts = {
            "api_keys": [],
            "tokens": [],
            "webhooks": [],
            "cdn_urls": [],
            "analytics_urls": []
        }
        
        # API key patterns
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'apikey["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']'
        ]
        
        # Token patterns
        token_patterns = [
            r'token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'bearer["\']?\s*[:=]\s*["\']([^"\']{10,})["\']'
        ]
        
        # Webhook patterns
        webhook_patterns = [
            r'webhook["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']',
            r'hook["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']'
        ]
        
        # CDN patterns
        cdn_patterns = [
            r'https?://[^/]*cdn[^/]*/[^\s"\'<>]+',
            r'https?://[^/]*cloudfront[^/]*/[^\s"\'<>]+',
            r'https?://[^/]*akamai[^/]*/[^\s"\'<>]+'
        ]
        
        # Analytics patterns
        analytics_patterns = [
            r'https?://[^/]*google-analytics[^/]*/[^\s"\'<>]+',
            r'https?://[^/]*googletagmanager[^/]*/[^\s"\'<>]+',
            r'https?://[^/]*facebook[^/]*/[^\s"\'<>]+',
            r'https?://[^/]*mixpanel[^/]*/[^\s"\'<>]+'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt', '.json', '.properties', '.java')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Extract API keys
                        for pattern in api_key_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                artifacts["api_keys"].append({
                                    "key": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract tokens
                        for pattern in token_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                artifacts["tokens"].append({
                                    "token": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract webhooks
                        for pattern in webhook_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                artifacts["webhooks"].append({
                                    "webhook": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract CDN URLs
                        for pattern in cdn_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                artifacts["cdn_urls"].append({
                                    "url": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                        # Extract analytics URLs
                        for pattern in analytics_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                artifacts["analytics_urls"].append({
                                    "url": match,
                                    "file": str(file_path.relative_to(self.extract_dir)),
                                    "context": self._get_context(content, match)
                                })
                        
                    except Exception:
                        continue
        
        # Remove duplicates
        for artifact_type in artifacts:
            artifacts[artifact_type] = self._remove_duplicates(artifacts[artifact_type], 
                "key" if artifact_type == "api_keys" else 
                "token" if artifact_type == "tokens" else 
                "webhook" if artifact_type == "webhooks" else "url")
        
        return artifacts
    
    def _calculate_statistics(self, results):
        """Calculate statistics for the analysis"""
        stats = {
            "total_urls": 0,
            "total_emails": 0,
            "total_endpoints": 0,
            "total_domains": 0,
            "total_hashes": 0
        }
        
        # Count URLs
        for url_type in results["urls"].values():
            stats["total_urls"] += len(url_type)
        
        # Count emails
        stats["total_emails"] = len(results["emails"])
        
        # Count endpoints
        for endpoint_type in results["endpoints"].values():
            stats["total_endpoints"] += len(endpoint_type)
        
        # Count domains
        stats["total_domains"] = len(results["domains"]["unique_domains"])
        
        # Count hashes
        for hash_type in results["hashes"].values():
            stats["total_hashes"] += len(hash_type)
        
        return stats
    
    # Helper methods
    def _is_valid_md5(self, hash_str):
        """Check if string is a valid MD5 hash"""
        return len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str)
    
    def _is_valid_sha1(self, hash_str):
        """Check if string is a valid SHA1 hash"""
        return len(hash_str) == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_str)
    
    def _is_valid_sha256(self, hash_str):
        """Check if string is a valid SHA256 hash"""
        return len(hash_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_str)
    
    def _is_valid_base64(self, string):
        """Check if string is valid Base64"""
        try:
            # Check if it's a valid base64 string
            if len(string) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in string):
                return True
        except:
            pass
        return False
    
    def _try_decode_base64(self, string):
        """Try to decode base64 string"""
        try:
            decoded = base64.b64decode(string).decode('utf-8')
            return decoded
        except:
            return None
    
    def _get_context(self, content, match, context_length=50):
        """Get context around a match"""
        try:
            index = content.find(match)
            if index != -1:
                start = max(0, index - context_length)
                end = min(len(content), index + len(match) + context_length)
                return content[start:end].replace('\n', ' ').strip()
        except:
            pass
        return ""
    
    def _analyze_url(self, url, file_path):
        """Analyze a URL and extract information"""
        try:
            parsed = urlparse(url)
            return {
                "url": url,
                "scheme": parsed.scheme,
                "domain": parsed.netloc,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "file": str(file_path.relative_to(self.extract_dir)),
                "parameters": parse_qs(parsed.query) if parsed.query else {}
            }
        except:
            return None
    
    def _analyze_endpoint(self, endpoint, file_path, endpoint_type):
        """Analyze an endpoint and extract information"""
        try:
            parsed = urlparse(endpoint)
            return {
                "endpoint": endpoint,
                "type": endpoint_type,
                "scheme": parsed.scheme,
                "domain": parsed.netloc,
                "path": parsed.path,
                "query": parsed.query,
                "file": str(file_path.relative_to(self.extract_dir)),
                "parameters": parse_qs(parsed.query) if parsed.query else {}
            }
        except:
            return None
    
    def _remove_duplicates(self, items, key_field):
        """Remove duplicate items based on a key field"""
        seen = set()
        unique_items = []
        for item in items:
            key = item.get(key_field)
            if key and key not in seen:
                seen.add(key)
                unique_items.append(item)
        return unique_items 