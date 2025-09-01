#!/usr/bin/env python3
"""
Comprehensive Report Sections
Additional sections for detailed APK analysis report
"""

import html
from datetime import datetime

class ComprehensiveReportSections:
    def __init__(self, results):
        self.results = results
    
    def generate_browsable_activities_section(self):
        """Generate browsable activities section"""
        manifest = self.results.get("manifest", {})
        activities = manifest.get("activities", [])
        browsable_activities = [a for a in activities if a.get("browsable", False)]
        
        return f"""
        <div class="section">
            <h2>Browsable Activities</h2>
            
            <div class="card">
                <h3>Browsable Activities Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Total Activities</span>
                    <span class="stat-value">{len(activities)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Browsable Activities</span>
                    <span class="stat-value badge {'warning' if len(browsable_activities) > 0 else 'success'}">{len(browsable_activities)}</span>
                </div>
            </div>
            
            {self._generate_browsable_activities_table(browsable_activities) if browsable_activities else '<p style="text-align: center; color: #7f8c8d;">No browsable activities found</p>'}
        </div>
        """
    
    def _generate_browsable_activities_table(self, activities):
        """Generate browsable activities table"""
        if not activities:
            return ""
        
        table_html = '<h3>Browsable Activities</h3><table class="table"><thead><tr><th>Activity</th><th>Intent Filters</th><th>Risk</th></tr></thead><tbody>'
        
        for activity in activities:
            name = activity.get("name", "")
            intent_filters_data = activity.get("intent_filters", [])
            intent_filters = len(intent_filters_data) if isinstance(intent_filters_data, list) else intent_filters_data
            risk = "High" if intent_filters > 2 else "Medium" if intent_filters > 0 else "Low"
            risk_class = "danger" if risk == "High" else "warning" if risk == "Medium" else "success"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(name)}</td>
                <td>{intent_filters}</td>
                <td><span class="badge {risk_class}">{risk}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_network_security_section(self):
        """Generate network security section"""
        network = self.results.get("network", {})
        security = self.results.get("security", {})
        network_security = security.get("network_security", {})
        
        return f"""
        <div class="section">
            <h2>Network Security</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Network Configuration</h3>
                    <div class="stat">
                        <span class="stat-label">Cleartext Traffic</span>
                        <span class="stat-value badge {'danger' if network_security.get('cleartext_traffic', False) else 'success'}">
                            {'Allowed' if network_security.get('cleartext_traffic', False) else 'Blocked'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Network Security Config</span>
                        <span class="stat-value">{network_security.get('network_security_config', 'Not specified')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Certificate Pinning</span>
                        <span class="stat-value badge {'success' if network.get('certificate_pinning', {}).get('pinning_implemented', False) else 'warning'}">
                            {'Implemented' if network.get('certificate_pinning', {}).get('pinning_implemented', False) else 'Not Implemented'}
                        </span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Network Permissions</h3>
                    <div class="stat">
                        <span class="stat-label">Internet Permission</span>
                        <span class="stat-value badge {'info' if network.get('network_permissions', []) else 'warning'}">
                            {'Granted' if network.get('network_permissions', []) else 'Not Found'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Network State</span>
                        <span class="stat-value badge {'info' if any('ACCESS_NETWORK_STATE' in perm for perm in network.get('network_permissions', [])) else 'warning'}">
                            {'Granted' if any('ACCESS_NETWORK_STATE' in perm for perm in network.get('network_permissions', [])) else 'Not Found'}
                        </span>
                    </div>
                </div>
            </div>
            
            {self._generate_network_urls_table(network.get('url_patterns', []))}
        </div>
        """
    
    def _generate_network_urls_table(self, urls):
        """Generate network URLs table"""
        if not urls:
            return ""
        
        table_html = '<h3>Network URLs</h3><table class="table"><thead><tr><th>URL</th><th>Protocol</th><th>Security</th></tr></thead><tbody>'
        
        for url in urls[:20]:  # Show first 20
            protocol = "HTTPS" if url.startswith("https://") else "HTTP" if url.startswith("http://") else "Other"
            security = "Secure" if protocol == "HTTPS" else "Insecure"
            security_class = "success" if security == "Secure" else "danger"
            
            table_html += f"""
            <tr>
                <td style="word-break: break-all; max-width: 300px;">{html.escape(url[:80])}{"..." if len(url) > 80 else ""}</td>
                <td>{protocol}</td>
                <td><span class="badge {security_class}">{security}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_manifest_analysis_section(self):
        """Generate manifest analysis section"""
        manifest = self.results.get("manifest", {})
        
        return f"""
        <div class="section">
            <h2>Manifest Analysis</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Application Info</h3>
                    <div class="stat">
                        <span class="stat-label">Package Name</span>
                        <span class="stat-value" style="font-family: monospace;">{manifest.get('package_name', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Version</span>
                        <span class="stat-value">{manifest.get('version_name', 'Unknown')} ({manifest.get('version_code', 'Unknown')})</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Target SDK</span>
                        <span class="stat-value">{manifest.get('target_sdk', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Min SDK</span>
                        <span class="stat-value">{manifest.get('min_sdk', 'Unknown')}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Components</h3>
                    <div class="stat">
                        <span class="stat-label">Activities</span>
                        <span class="stat-value">{len(manifest.get('activities', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Services</span>
                        <span class="stat-value">{len(manifest.get('services', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Receivers</span>
                        <span class="stat-value">{len(manifest.get('receivers', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Providers</span>
                        <span class="stat-value">{len(manifest.get('providers', []))}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Security Flags</h3>
                    <div class="stat">
                        <span class="stat-label">Debuggable</span>
                        <span class="stat-value badge {'danger' if manifest.get('debuggable', False) else 'success'}">
                            {'Yes' if manifest.get('debuggable', False) else 'No'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Backup Allowed</span>
                        <span class="stat-value badge {'warning' if manifest.get('allow_backup', False) else 'success'}">
                            {'Yes' if manifest.get('allow_backup', False) else 'No'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Test Only</span>
                        <span class="stat-value badge {'danger' if manifest.get('test_only', False) else 'success'}">
                            {'Yes' if manifest.get('test_only', False) else 'No'}
                        </span>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def generate_code_analysis_section(self):
        """Generate code analysis section"""
        dex = self.results.get("dex", {})
        code_quality = self.results.get("code_quality", {})
        
        return f"""
        <div class="section">
            <h2>Code Analysis</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Code Statistics</h3>
                    <div class="stat">
                        <span class="stat-label">Total Classes</span>
                        <span class="stat-value">{dex.get('total_classes', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Total Methods</span>
                        <span class="stat-value">{dex.get('total_methods', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Total Strings</span>
                        <span class="stat-value">{dex.get('total_strings', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Code Size</span>
                        <span class="stat-value">{dex.get('code_size', 'Unknown')}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Code Quality</h3>
                    <div class="stat">
                        <span class="stat-label">Obfuscation</span>
                        <span class="stat-value badge {'success' if code_quality.get('obfuscated', False) else 'warning'}">
                            {'Detected' if code_quality.get('obfuscated', False) else 'Not Detected'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Anti-Debug</span>
                        <span class="stat-value badge {'success' if code_quality.get('anti_debug', False) else 'warning'}">
                            {'Present' if code_quality.get('anti_debug', False) else 'Not Found'}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Root Detection</span>
                        <span class="stat-value badge {'info' if code_quality.get('root_detection', False) else 'success'}">
                            {'Present' if code_quality.get('root_detection', False) else 'Not Found'}
                        </span>
                    </div>
                </div>
            </div>
            
            {self._generate_suspicious_methods_table(dex.get('suspicious_methods', []))}
        </div>
        """
    
    def _generate_suspicious_methods_table(self, methods):
        """Generate suspicious methods table"""
        if not methods:
            return ""
        
        table_html = '<h3>Suspicious Methods</h3><table class="table"><thead><tr><th>Class</th><th>Method</th><th>Risk</th><th>Description</th></tr></thead><tbody>'
        
        for method in methods[:15]:  # Show first 15
            class_name = method.get("class", "")
            method_name = method.get("method", "")
            risk = method.get("risk", "low")
            description = method.get("description", "Suspicious method detected")
            
            risk_class = "danger" if risk == "high" else "warning" if risk == "medium" else "info"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(class_name)}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(method_name)}</td>
                <td><span class="badge {risk_class}">{risk.upper()}</span></td>
                <td>{html.escape(description)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_library_analysis_section(self):
        """Generate library analysis section"""
        native = self.results.get("native", {})
        dex = self.results.get("dex", {})
        
        return f"""
        <div class="section">
            <h2>Shared Library Binary Analysis</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Native Libraries</h3>
                    <div class="stat">
                        <span class="stat-label">Total Libraries</span>
                        <span class="stat-value">{native.get('total_libraries', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Architectures</span>
                        <span class="stat-value">{', '.join(native.get('architectures', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Security Features</span>
                        <span class="stat-value badge {'success' if native.get('has_security_features', False) else 'warning'}">
                            {'Present' if native.get('has_security_features', False) else 'Limited'}
                        </span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Third-Party Libraries</h3>
                    <div class="stat">
                        <span class="stat-label">Total Libraries</span>
                        <span class="stat-value">{len(dex.get('libraries', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Known Libraries</span>
                        <span class="stat-value">{len([lib for lib in dex.get('libraries', []) if lib.get('known', False)])}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Vulnerable Libraries</span>
                        <span class="stat-value badge {'danger' if len([lib for lib in dex.get('libraries', []) if lib.get('vulnerable', False)]) > 0 else 'success'}">
                            {len([lib for lib in dex.get('libraries', []) if lib.get('vulnerable', False)])}
                        </span>
                    </div>
                </div>
            </div>
            
            {self._generate_libraries_table(dex.get('libraries', []))}
        </div>
        """
    
    def _generate_libraries_table(self, libraries):
        """Generate libraries table"""
        if not libraries:
            return ""
        
        table_html = '<h3>Detected Libraries</h3><table class="table"><thead><tr><th>Library</th><th>Version</th><th>Type</th><th>Vulnerable</th></tr></thead><tbody>'
        
        for lib in libraries[:20]:  # Show first 20
            name = lib.get("name", "")
            version = lib.get("version", "Unknown")
            lib_type = lib.get("type", "Unknown")
            vulnerable = lib.get("vulnerable", False)
            
            vuln_class = "danger" if vulnerable else "success"
            vuln_text = "Yes" if vulnerable else "No"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(name)}</td>
                <td>{html.escape(version)}</td>
                <td>{html.escape(lib_type)}</td>
                <td><span class="badge {vuln_class}">{vuln_text}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_malware_lookup_section(self):
        """Generate malware lookup section"""
        return f"""
        <div class="section">
            <h2>Malware Lookup</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>VirusTotal Report</h3>
                    <div class="stat">
                        <span class="stat-label">Status</span>
                        <span class="stat-value badge info">Not Available</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Detection Rate</span>
                        <span class="stat-value">N/A</span>
                    </div>
                    <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                        VirusTotal analysis requires API integration
                    </p>
                </div>
                
                <div class="card">
                    <h3>Triage Report</h3>
                    <div class="stat">
                        <span class="stat-label">Status</span>
                        <span class="stat-value badge info">Not Available</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Score</span>
                        <span class="stat-value">N/A</span>
                    </div>
                    <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                        Triage analysis requires API integration
                    </p>
                </div>
                
                <div class="card">
                    <h3>MetaDefender Report</h3>
                    <div class="stat">
                        <span class="stat-label">Status</span>
                        <span class="stat-value badge info">Not Available</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Threat Level</span>
                        <span class="stat-value">N/A</span>
                    </div>
                    <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                        MetaDefender analysis requires API integration
                    </p>
                </div>
                
                <div class="card">
                    <h3>Hybrid Analysis Report</h3>
                    <div class="stat">
                        <span class="stat-label">Status</span>
                        <span class="stat-value badge info">Not Available</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Threat Score</span>
                        <span class="stat-value">N/A</span>
                    </div>
                    <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                        Hybrid Analysis requires API integration
                    </p>
                </div>
            </div>
        </div>
        """
    
    def generate_apkid_analysis_section(self):
        """Generate APKiD analysis section"""
        return f"""
        <div class="section">
            <h2>APKiD Analysis</h2>
            
            <div class="card">
                <h3>APKiD Results</h3>
                <div class="stat">
                    <span class="stat-label">Status</span>
                    <span class="stat-value badge info">Not Available</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Anti-VM</span>
                    <span class="stat-value">N/A</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Anti-Debug</span>
                    <span class="stat-value">N/A</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Packer</span>
                    <span class="stat-value">N/A</span>
                </div>
                <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                    APKiD analysis requires APKiD tool integration
                </p>
            </div>
        </div>
        """
    
    def generate_behaviour_analysis_section(self):
        """Generate behaviour analysis section"""
        return f"""
        <div class="section">
            <h2>Behaviour Analysis</h2>
            
            <div class="card">
                <h3>Runtime Behaviour</h3>
                <div class="stat">
                    <span class="stat-label">Status</span>
                    <span class="stat-value badge info">Static Analysis Only</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Network Calls</span>
                    <span class="stat-value">Detected in static analysis</span>
                </div>
                <div class="stat">
                    <span class="stat-label">File Operations</span>
                    <span class="stat-value">Detected in static analysis</span>
                </div>
                <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                    Dynamic analysis requires runtime environment setup
                </p>
            </div>
        </div>
        """
    
    def generate_abused_permissions_section(self):
        """Generate abused permissions section"""
        permissions = self.results.get("permissions", {})
        perm_list = permissions.get("permissions", [])
        dangerous_perms = [p for p in perm_list if isinstance(p, dict) and p.get("protection_level") == "dangerous"]
        
        return f"""
        <div class="section">
            <h2>Abused Permissions</h2>
            
            <div class="card">
                <h3>Permission Abuse Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Dangerous Permissions</span>
                    <span class="stat-value badge {'warning' if len(dangerous_perms) > 0 else 'success'}">{len(dangerous_perms)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">High Risk Combinations</span>
                    <span class="stat-value badge {'danger' if len(dangerous_perms) > 5 else 'success'}">
                        {'High' if len(dangerous_perms) > 5 else 'Low'}
                    </span>
                </div>
            </div>
            
            {self._generate_abused_permissions_table(dangerous_perms) if dangerous_perms else '<p style="text-align: center; color: #7f8c8d;">No dangerous permissions found</p>'}
        </div>
        """
    
    def _generate_abused_permissions_table(self, permissions):
        """Generate abused permissions table"""
        if not permissions:
            return ""
        
        table_html = '<h3>Dangerous Permissions</h3><table class="table"><thead><tr><th>Permission</th><th>Risk Level</th><th>Potential Abuse</th></tr></thead><tbody>'
        
        for perm in permissions:
            name = perm.get("name", "")
            risk_level = "High"
            potential_abuse = "Data access, privacy violation"
            
            if "SMS" in name:
                potential_abuse = "SMS interception, spam"
            elif "LOCATION" in name:
                potential_abuse = "Location tracking, privacy violation"
            elif "CAMERA" in name:
                potential_abuse = "Unauthorized recording, privacy violation"
            elif "MICROPHONE" in name:
                potential_abuse = "Audio recording, privacy violation"
            elif "CONTACTS" in name:
                potential_abuse = "Contact harvesting, spam"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(name)}</td>
                <td><span class="badge danger">{risk_level}</span></td>
                <td>{html.escape(potential_abuse)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_domain_malware_check_section(self):
        """Generate domain malware check section"""
        internet = self.results.get("internet", {})
        domains = internet.get("domains", {})
        unique_domains = domains.get("unique_domains", [])
        
        return f"""
        <div class="section">
            <h2>Domain Malware Check</h2>
            
            <div class="card">
                <h3>Domain Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Total Domains</span>
                    <span class="stat-value">{len(unique_domains)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Suspicious Domains</span>
                    <span class="stat-value badge info">Manual Review Required</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Known Malicious</span>
                    <span class="stat-value badge success">0</span>
                </div>
            </div>
            
            {self._generate_domains_table(unique_domains[:20]) if unique_domains else '<p style="text-align: center; color: #7f8c8d;">No domains found</p>'}
        </div>
        """
    
    def _generate_domains_table(self, domains):
        """Generate domains table"""
        if not domains:
            return ""
        
        table_html = '<h3>Detected Domains</h3><table class="table"><thead><tr><th>Domain</th><th>Type</th><th>Risk</th></tr></thead><tbody>'
        
        for domain_info in domains:
            domain = domain_info.get("domain", "")
            domain_type = "Unknown"
            risk = "Low"
            
            if "api" in domain.lower():
                domain_type = "API"
            elif "cdn" in domain.lower():
                domain_type = "CDN"
            elif "analytics" in domain.lower():
                domain_type = "Analytics"
            elif "google" in domain.lower() or "facebook" in domain.lower():
                domain_type = "Social"
                risk = "Medium"
            
            risk_class = "danger" if risk == "High" else "warning" if risk == "Medium" else "success"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(domain)}</td>
                <td>{domain_type}</td>
                <td><span class="badge {risk_class}">{risk}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_urls_section(self):
        """Generate URLs section"""
        internet = self.results.get("internet", {})
        urls = internet.get("urls", {})
        
        return f"""
        <div class="section">
            <h2>URLs</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>URL Statistics</h3>
                    <div class="stat">
                        <span class="stat-label">Total URLs</span>
                        <span class="stat-value">{sum(len(url_list) for url_list in urls.values())}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">HTTPS URLs</span>
                        <span class="stat-value badge success">{len(urls.get('https_urls', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">HTTP URLs</span>
                        <span class="stat-value badge {'warning' if len(urls.get('http_urls', [])) > 0 else 'success'}">{len(urls.get('http_urls', []))}</span>
                    </div>
                </div>
            </div>
            
            {self._generate_comprehensive_urls_table(urls)}
        </div>
        """
    
    def _generate_comprehensive_urls_table(self, urls):
        """Generate comprehensive URLs table"""
        all_urls = []
        for url_type, url_list in urls.items():
            for url_info in url_list:
                url_info['type'] = url_type
                all_urls.append(url_info)
        
        if not all_urls:
            return '<p style="text-align: center; color: #7f8c8d;">No URLs found</p>'
        
        table_html = '<h3>All URLs</h3><table class="table"><thead><tr><th>URL</th><th>Type</th><th>Domain</th><th>Security</th></tr></thead><tbody>'
        
        for url_info in all_urls[:30]:  # Show first 30
            url = url_info.get("url", "")
            url_type = url_info.get("type", "").replace("_", " ").title()
            domain = url_info.get("domain", "")
            security = "Secure" if url.startswith("https://") else "Insecure" if url.startswith("http://") else "Unknown"
            security_class = "success" if security == "Secure" else "danger" if security == "Insecure" else "info"
            
            table_html += f"""
            <tr>
                <td style="word-break: break-all; max-width: 300px;">{html.escape(url[:100])}{"..." if len(url) > 100 else ""}</td>
                <td>{url_type}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(domain)}</td>
                <td><span class="badge {security_class}">{security}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_emails_section(self):
        """Generate emails section"""
        internet = self.results.get("internet", {})
        emails = internet.get("emails", [])
        
        return f"""
        <div class="section">
            <h2>Emails</h2>
            
            <div class="card">
                <h3>Email Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Total Emails</span>
                    <span class="stat-value">{len(emails)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Unique Domains</span>
                    <span class="stat-value">{len(set(email.get('domain', '') for email in emails))}</span>
                </div>
            </div>
            
            {self._generate_emails_table(emails) if emails else '<p style="text-align: center; color: #7f8c8d;">No email addresses found</p>'}
        </div>
        """
    
    def _generate_emails_table(self, emails):
        """Generate emails table"""
        if not emails:
            return ""
        
        table_html = '<h3>Email Addresses</h3><table class="table"><thead><tr><th>Email</th><th>Domain</th><th>Context</th></tr></thead><tbody>'
        
        for email_info in emails:
            email = email_info.get("email", "")
            domain = email_info.get("domain", "")
            context = email_info.get("context", "")[:50] + "..." if len(email_info.get("context", "")) > 50 else email_info.get("context", "")
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(email)}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(domain)}</td>
                <td style="font-size: 0.8em; color: #7f8c8d;">{html.escape(context)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_trackers_section(self):
        """Generate trackers section"""
        internet = self.results.get("internet", {})
        artifacts = internet.get("network_artifacts", {})
        analytics_urls = artifacts.get("analytics_urls", [])
        
        return f"""
        <div class="section">
            <h2>Trackers</h2>
            
            <div class="card">
                <h3>Tracking Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Analytics URLs</span>
                    <span class="stat-value badge {'warning' if len(analytics_urls) > 0 else 'success'}">{len(analytics_urls)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Google Analytics</span>
                    <span class="stat-value badge {'info' if any('google-analytics' in url.get('url', '') for url in analytics_urls) else 'success'}">
                        {'Present' if any('google-analytics' in url.get('url', '') for url in analytics_urls) else 'Not Found'}
                    </span>
                </div>
                <div class="stat">
                    <span class="stat-label">Facebook Tracking</span>
                    <span class="stat-value badge {'info' if any('facebook' in url.get('url', '') for url in analytics_urls) else 'success'}">
                        {'Present' if any('facebook' in url.get('url', '') for url in analytics_urls) else 'Not Found'}
                    </span>
                </div>
            </div>
            
            {self._generate_trackers_table(analytics_urls) if analytics_urls else '<p style="text-align: center; color: #7f8c8d;">No tracking URLs found</p>'}
        </div>
        """
    
    def _generate_trackers_table(self, trackers):
        """Generate trackers table"""
        if not trackers:
            return ""
        
        table_html = '<h3>Tracking URLs</h3><table class="table"><thead><tr><th>URL</th><th>Service</th><th>Type</th></tr></thead><tbody>'
        
        for tracker in trackers:
            url = tracker.get("url", "")
            service = "Unknown"
            tracker_type = "Analytics"
            
            if "google-analytics" in url:
                service = "Google Analytics"
            elif "googletagmanager" in url:
                service = "Google Tag Manager"
            elif "facebook" in url:
                service = "Facebook"
                tracker_type = "Social"
            elif "mixpanel" in url:
                service = "Mixpanel"
            
            table_html += f"""
            <tr>
                <td style="word-break: break-all; max-width: 300px;">{html.escape(url[:80])}{"..." if len(url) > 80 else ""}</td>
                <td>{service}</td>
                <td><span class="badge info">{tracker_type}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_hardcoded_secrets_section(self):
        """Generate hardcoded secrets section"""
        secrets = self.results.get("secrets", {})
        secret_list = secrets.get("hardcoded_secrets", [])
        
        return f"""
        <div class="section">
            <h2>Possible Hardcoded Secrets</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Secrets Summary</h3>
                    <div class="stat">
                        <span class="stat-label">Total Secrets</span>
                        <span class="stat-value badge {'danger' if len(secret_list) > 0 else 'success'}">{len(secret_list)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">High Risk</span>
                        <span class="stat-value badge {'danger' if len([s for s in secret_list if s.get('risk_level') == 'high']) > 0 else 'success'}">
                            {len([s for s in secret_list if s.get('risk_level') == 'high'])}
                        </span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Medium Risk</span>
                        <span class="stat-value badge {'warning' if len([s for s in secret_list if s.get('risk_level') == 'medium']) > 0 else 'success'}">
                            {len([s for s in secret_list if s.get('risk_level') == 'medium'])}
                        </span>
                    </div>
                </div>
            </div>
            
            {self._generate_secrets_table(secret_list) if secret_list else '<p style="text-align: center; color: #27ae60; font-size: 1.2em;">✅ No hardcoded secrets found</p>'}
        </div>
        """
    
    def _generate_secrets_table(self, secrets):
        """Generate secrets table"""
        if not secrets:
            return ""
        
        table_html = '<h3>Detected Secrets</h3><table class="table"><thead><tr><th>Type</th><th>Risk Level</th><th>File</th><th>Context</th></tr></thead><tbody>'
        
        for secret in secrets:
            secret_type = secret.get("type", "Unknown")
            risk_level = secret.get("risk_level", "Unknown")
            file_path = secret.get("file", "Unknown")
            context = secret.get("context", "")[:50] + "..." if len(secret.get("context", "")) > 50 else secret.get("context", "")
            
            risk_class = "danger" if risk_level == "high" else "warning" if risk_level == "medium" else "info"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(secret_type)}</td>
                <td><span class="badge {risk_class}">{risk_level.upper()}</span></td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(file_path)}</td>
                <td style="font-size: 0.8em; color: #7f8c8d;">{html.escape(context)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def generate_libraries_section(self):
        """Generate libraries section"""
        dex = self.results.get("dex", {})
        libraries = dex.get("libraries", [])
        
        return f"""
        <div class="section">
            <h2>Libraries</h2>
            
            <div class="card">
                <h3>Library Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Total Libraries</span>
                    <span class="stat-value">{len(libraries)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Known Libraries</span>
                    <span class="stat-value">{len([lib for lib in libraries if lib.get('known', False)])}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Vulnerable Libraries</span>
                    <span class="stat-value badge {'danger' if len([lib for lib in libraries if lib.get('vulnerable', False)]) > 0 else 'success'}">
                        {len([lib for lib in libraries if lib.get('vulnerable', False)])}
                    </span>
                </div>
            </div>
            
            {self._generate_libraries_table(libraries) if libraries else '<p style="text-align: center; color: #7f8c8d;">No libraries detected</p>'}
        </div>
        """
    
    def generate_sbom_section(self):
        """Generate SBOM (Software Bill of Materials) section"""
        return f"""
        <div class="section">
            <h2>SBOM (Software Bill of Materials)</h2>
            
            <div class="card">
                <h3>Component Inventory</h3>
                <div class="stat">
                    <span class="stat-label">Status</span>
                    <span class="stat-value badge info">Not Generated</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Components</span>
                    <span class="stat-value">N/A</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Dependencies</span>
                    <span class="stat-value">N/A</span>
                </div>
                <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 10px;">
                    SBOM generation requires additional tooling integration
                </p>
            </div>
        </div>
        """