#!/usr/bin/env python3
"""
Clean Report Generator
Simple, clean, and minimal HTML report generator for APK analysis
"""

import html
import json
from datetime import datetime
from modules.comprehensive_report_sections import ComprehensiveReportSections

class CleanReportGenerator:
    def __init__(self, results, output_dir):
        self.results = results
        self.output_dir = output_dir
        
    def generate_report(self):
        """Generate clean HTML report"""
        html_content = self._create_html_report()
        
        # Save HTML report
        report_path = self.output_dir / "security_report.html"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Clean HTML report generated: {report_path}")
    
    def _create_html_report(self):
        """Create clean HTML report"""
        security_score = self.results.get("security", {}).get("security_score", 0)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }}
        
        .header p {{
            color: #7f8c8d;
            font-size: 1.1em;
        }}
        
        .score-card {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .score {{
            font-size: 4em;
            font-weight: 300;
            margin-bottom: 10px;
        }}
        
        .score.good {{ color: #27ae60; }}
        .score.warning {{ color: #f39c12; }}
        .score.danger {{ color: #e74c3c; }}
        
        .score-label {{
            color: #7f8c8d;
            font-size: 1.2em;
            margin-bottom: 20px;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .progress-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        
        .progress-fill.good {{ background: #27ae60; }}
        .progress-fill.warning {{ background: #f39c12; }}
        .progress-fill.danger {{ background: #e74c3c; }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .card h3 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
            font-weight: 500;
        }}
        
        .stat {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .stat:last-child {{
            border-bottom: none;
        }}
        
        .stat-label {{
            color: #7f8c8d;
        }}
        
        .stat-value {{
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .badge.success {{ background: #d5f4e6; color: #27ae60; }}
        .badge.warning {{ background: #fef5e7; color: #f39c12; }}
        .badge.danger {{ background: #fadbd8; color: #e74c3c; }}
        .badge.info {{ background: #e3f2fd; color: #3498db; }}
        
        .section {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            font-weight: 400;
        }}
        
        .vulnerability {{
            padding: 20px;
            border-left: 4px solid #e74c3c;
            background: #fdf2f2;
            border-radius: 0 8px 8px 0;
            margin-bottom: 15px;
        }}
        
        .vulnerability.medium {{
            border-left-color: #f39c12;
            background: #fef9e7;
        }}
        
        .vulnerability.low {{
            border-left-color: #27ae60;
            background: #f0f9f0;
        }}
        
        .vulnerability h4 {{
            color: #2c3e50;
            margin-bottom: 8px;
        }}
        
        .vulnerability p {{
            color: #7f8c8d;
            margin-bottom: 5px;
        }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .table th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 500;
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
        }}
        
        .table td {{
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .table tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            text-align: center;
            color: #7f8c8d;
            margin-top: 50px;
            padding: 20px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>APK Security Analysis</h1>
            <p>Comprehensive security assessment report</p>
        </div>
        
        <div class="score-card">
            <div class="score {'good' if security_score >= 70 else 'warning' if security_score >= 40 else 'danger'}">
                {security_score}
            </div>
            <div class="score-label">Security Score</div>
            <div class="progress-bar">
                <div class="progress-fill {'good' if security_score >= 70 else 'warning' if security_score >= 40 else 'danger'}" 
                     style="width: {security_score}%"></div>
            </div>
        </div>
        
        {self._generate_overview_section()}
        {self._generate_permissions_section()}
        {self._generate_certificate_section()}
        {self._generate_file_info_section()}
        {self._generate_android_api_section()}
        {self._generate_browsable_activities_section()}
        {self._generate_network_security_section()}
        {self._generate_manifest_analysis_section()}
        {self._generate_code_analysis_section()}
        {self._generate_library_analysis_section()}
        {self._generate_malware_lookup_section()}
        {self._generate_apkid_analysis_section()}
        {self._generate_behaviour_analysis_section()}
        {self._generate_abused_permissions_section()}
        {self._generate_domain_malware_check_section()}
        {self._generate_urls_section()}
        {self._generate_emails_section()}
        {self._generate_trackers_section()}
        {self._generate_hardcoded_secrets_section()}
        {self._generate_libraries_section()}
        {self._generate_sbom_section()}
        {self._generate_vulnerabilities_section()}
        
        <div class="footer">
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _generate_overview_section(self):
        """Generate overview section"""
        security = self.results.get("security", {})
        vulnerabilities = security.get("vulnerability_summary", [])
        
        high_vulns = len([v for v in vulnerabilities if v.get("risk") in ["Critical", "High"]])
        medium_vulns = len([v for v in vulnerabilities if v.get("risk") == "Medium"])
        low_vulns = len([v for v in vulnerabilities if v.get("risk") == "Low"])
        
        secrets = self.results.get("secrets", {})
        secrets_count = len(secrets.get("hardcoded_secrets", []))
        
        permissions = self.results.get("permissions", {})
        dangerous_perms = len([p for p in permissions.get("permissions", []) 
                             if isinstance(p, dict) and p.get("protection_level") == "dangerous"])
        
        internet = self.results.get("internet", {})
        internet_stats = internet.get("statistics", {})
        total_urls = internet_stats.get("total_urls", 0)
        total_emails = internet_stats.get("total_emails", 0)
        
        return f"""
        <div class="section">
            <h2>Overview</h2>
            <div class="grid">
                <div class="card">
                    <h3>Vulnerabilities</h3>
                    <div class="stat">
                        <span class="stat-label">High Risk</span>
                        <span class="stat-value badge {'danger' if high_vulns > 0 else 'success'}">{high_vulns}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Medium Risk</span>
                        <span class="stat-value badge {'warning' if medium_vulns > 0 else 'success'}">{medium_vulns}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Low Risk</span>
                        <span class="stat-value badge {'info' if low_vulns > 0 else 'success'}">{low_vulns}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Security Issues</h3>
                    <div class="stat">
                        <span class="stat-label">Hardcoded Secrets</span>
                        <span class="stat-value badge {'danger' if secrets_count > 0 else 'success'}">{secrets_count}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Dangerous Permissions</span>
                        <span class="stat-value badge {'warning' if dangerous_perms > 5 else 'success'}">{dangerous_perms}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Internet Artifacts</h3>
                    <div class="stat">
                        <span class="stat-label">URLs Found</span>
                        <span class="stat-value">{total_urls}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Email Addresses</span>
                        <span class="stat-value">{total_emails}</span>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_vulnerabilities_section(self):
        """Generate vulnerabilities section"""
        security = self.results.get("security", {})
        vulnerabilities = security.get("vulnerability_summary", [])
        
        if not vulnerabilities:
            return """
            <div class="section">
                <h2>Security Vulnerabilities</h2>
                <div class="card">
                    <p style="text-align: center; color: #27ae60; font-size: 1.2em;">
                        ✅ No security vulnerabilities found
                    </p>
                </div>
            </div>
            """
        
        vuln_html = '<div class="section"><h2>Security Vulnerabilities</h2>'
        
        for vuln in vulnerabilities[:10]:  # Show first 10
            risk = vuln.get("risk", "Unknown")
            risk_class = "danger" if risk in ["Critical", "High"] else "medium" if risk == "Medium" else "low"
            
            vuln_html += f"""
            <div class="vulnerability {risk_class}">
                <h4>{html.escape(vuln.get("type", "Unknown Vulnerability"))}</h4>
                <p><strong>Risk:</strong> {risk}</p>
                <p><strong>Description:</strong> {html.escape(vuln.get("description", "No description"))}</p>
                {f'<p><strong>File:</strong> {html.escape(vuln.get("file", "Unknown"))}</p>' if vuln.get("file") else ''}
                {f'<p><strong>Remediation:</strong> {html.escape(vuln.get("remediation", ""))}</p>' if vuln.get("remediation") else ''}
            </div>
            """
        
        vuln_html += '</div>'
        return vuln_html
    
    def _generate_internet_section(self):
        """Generate internet artifacts section"""
        internet = self.results.get("internet", {})
        
        if not internet:
            return """
            <div class="section">
                <h2>Internet Artifacts</h2>
                <div class="card">
                    <p style="text-align: center; color: #7f8c8d;">
                        No internet artifacts found
                    </p>
                </div>
            </div>
            """
        
        stats = internet.get("statistics", {})
        urls = internet.get("urls", {})
        emails = internet.get("emails", [])
        hashes = internet.get("hashes", {})
        
        return f"""
        <div class="section">
            <h2>Internet Artifacts</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>URLs</h3>
                    <div class="stat">
                        <span class="stat-label">HTTPS URLs</span>
                        <span class="stat-value">{len(urls.get('https_urls', []))}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">HTTP URLs</span>
                        <span class="stat-value badge {'warning' if len(urls.get('http_urls', [])) > 0 else 'success'}">{len(urls.get('http_urls', []))}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Other Artifacts</h3>
                    <div class="stat">
                        <span class="stat-label">Email Addresses</span>
                        <span class="stat-value">{len(emails)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Hash Values</span>
                        <span class="stat-value">{stats.get('total_hashes', 0)}</span>
                    </div>
                </div>
            </div>
            
            {self._generate_urls_table(urls)}
            {self._generate_emails_table(emails)}
        </div>
        """
    
    def _generate_urls_table(self, urls):
        """Generate URLs table"""
        all_urls = []
        for url_type, url_list in urls.items():
            all_urls.extend(url_list[:5])  # Show first 5 of each type
        
        if not all_urls:
            return ""
        
        table_html = '<h3>Sample URLs</h3><table class="table"><thead><tr><th>Type</th><th>URL</th><th>Domain</th></tr></thead><tbody>'
        
        for url_info in all_urls[:10]:  # Show max 10
            url = url_info.get("url", "")
            domain = url_info.get("domain", "")
            url_type = "HTTPS" if url.startswith("https://") else "HTTP" if url.startswith("http://") else "Other"
            
            table_html += f"""
            <tr>
                <td><span class="badge {'success' if url_type == 'HTTPS' else 'warning'}">{url_type}</span></td>
                <td style="word-break: break-all; max-width: 300px;">{html.escape(url[:80])}{"..." if len(url) > 80 else ""}</td>
                <td>{html.escape(domain)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def _generate_emails_table(self, emails):
        """Generate emails table"""
        if not emails:
            return ""
        
        table_html = '<h3>Email Addresses</h3><table class="table"><thead><tr><th>Email</th><th>Domain</th></tr></thead><tbody>'
        
        for email_info in emails[:10]:  # Show max 10
            email = email_info.get("email", "")
            domain = email_info.get("domain", "")
            
            table_html += f"""
            <tr>
                <td>{html.escape(email)}</td>
                <td>{html.escape(domain)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def _generate_permissions_section(self):
        """Generate comprehensive permissions section"""
        permissions = self.results.get("permissions", {})
        perm_list = permissions.get("permissions", [])
        
        if not perm_list:
            return """
            <div class="section">
                <h2>Application Permissions</h2>
                <div class="card">
                    <p style="text-align: center; color: #7f8c8d;">
                        No permissions information available
                    </p>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>Application Permissions</h2>
            
            <table class="table">
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Status</th>
                        <th>Info</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_permissions_table_rows(perm_list)}
                </tbody>
            </table>
        </div>
        """
    
    def _generate_permissions_table(self, permissions, title):
        """Generate permissions table"""
        if not permissions:
            return ""
        
        table_html = f'<h3>{title}</h3><table class="table"><thead><tr><th>Permission</th><th>Description</th></tr></thead><tbody>'
        
        for perm in permissions[:10]:  # Show max 10
            name = perm.get("name", "")
            description = perm.get("description", "No description available")
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace;">{html.escape(name)}</td>
                <td>{html.escape(description)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def _generate_permissions_table_rows(self, permissions):
        """Generate permissions table rows"""
        rows = ""
        for perm in permissions:
            if isinstance(perm, dict):
                name = perm.get("name", "")
                protection_level = perm.get("protection_level", "unknown")
                description = perm.get("description", "No description available")
                
                # Determine status and info
                if protection_level == "dangerous":
                    status = '<span class="badge danger">DANGEROUS</span>'
                    info = "High Risk"
                elif protection_level == "signature":
                    status = '<span class="badge warning">SIGNATURE</span>'
                    info = "System Only"
                elif protection_level == "normal":
                    status = '<span class="badge success">NORMAL</span>'
                    info = "Low Risk"
                else:
                    status = '<span class="badge info">UNKNOWN</span>'
                    info = "Unknown"
                
                rows += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.9em;">{html.escape(name)}</td>
                    <td>{status}</td>
                    <td>{info}</td>
                    <td>{html.escape(description)}</td>
                </tr>
                """
        return rows
    
    def _generate_certificate_section(self):
        """Generate signer certificate section"""
        certificates = self.results.get("certificates", {})
        
        return f"""
        <div class="section">
            <h2>Signer Certificate</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Certificate Information</h3>
                    <div class="stat">
                        <span class="stat-label">Issuer</span>
                        <span class="stat-value">{certificates.get('issuer', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Subject</span>
                        <span class="stat-value">{certificates.get('subject', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Valid From</span>
                        <span class="stat-value">{certificates.get('valid_from', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Valid Until</span>
                        <span class="stat-value">{certificates.get('valid_until', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Serial Number</span>
                        <span class="stat-value" style="font-family: monospace; font-size: 0.8em;">{certificates.get('serial_number', 'Unknown')}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Security Analysis</h3>
                    <div class="stat">
                        <span class="stat-label">Signature Algorithm</span>
                        <span class="stat-value">{certificates.get('signature_algorithm', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Key Size</span>
                        <span class="stat-value">{certificates.get('key_size', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Certificate Status</span>
                        <span class="stat-value badge {'success' if certificates.get('is_valid', False) else 'danger'}">
                            {'Valid' if certificates.get('is_valid', False) else 'Invalid'}
                        </span>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_file_info_section(self):
        """Generate file information section"""
        structure = self.results.get("structure", {})
        
        return f"""
        <div class="section">
            <h2>File Information</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>APK Details</h3>
                    <div class="stat">
                        <span class="stat-label">Package Name</span>
                        <span class="stat-value" style="font-family: monospace;">{structure.get('package_name', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Version Name</span>
                        <span class="stat-value">{structure.get('version_name', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Version Code</span>
                        <span class="stat-value">{structure.get('version_code', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Target SDK</span>
                        <span class="stat-value">{structure.get('target_sdk', 'Unknown')}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Min SDK</span>
                        <span class="stat-value">{structure.get('min_sdk', 'Unknown')}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>File Structure</h3>
                    <div class="stat">
                        <span class="stat-label">Total Files</span>
                        <span class="stat-value">{structure.get('total_files', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">DEX Files</span>
                        <span class="stat-value">{structure.get('dex_files', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Native Libraries</span>
                        <span class="stat-value">{structure.get('native_libs', 0)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Assets</span>
                        <span class="stat-value">{structure.get('assets', 0)}</span>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_android_api_section(self):
        """Generate Android API analysis section"""
        dex = self.results.get("dex", {})
        api_calls = dex.get("api_calls", [])
        
        return f"""
        <div class="section">
            <h2>Android API</h2>
            
            <div class="card">
                <h3>API Usage Analysis</h3>
                <div class="stat">
                    <span class="stat-label">Total API Calls</span>
                    <span class="stat-value">{len(api_calls)}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Suspicious APIs</span>
                    <span class="stat-value badge {'warning' if len([api for api in api_calls if api.get('suspicious', False)]) > 0 else 'success'}">
                        {len([api for api in api_calls if api.get('suspicious', False)])}
                    </span>
                </div>
            </div>
            
            {self._generate_api_calls_table(api_calls[:20]) if api_calls else '<p style="text-align: center; color: #7f8c8d;">No API calls information available</p>'}
        </div>
        """
    
    def _generate_api_calls_table(self, api_calls):
        """Generate API calls table"""
        if not api_calls:
            return ""
        
        table_html = '<h3>API Calls</h3><table class="table"><thead><tr><th>API</th><th>Class</th><th>Method</th><th>Risk</th></tr></thead><tbody>'
        
        for api in api_calls:
            api_name = api.get("api", "")
            class_name = api.get("class", "")
            method_name = api.get("method", "")
            risk = api.get("risk", "low")
            
            risk_class = "danger" if risk == "high" else "warning" if risk == "medium" else "success"
            
            table_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(api_name)}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(class_name)}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(method_name)}</td>
                <td><span class="badge {risk_class}">{risk.upper()}</span></td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html
    
    def _generate_secrets_section(self):
        """Generate secrets section"""
        secrets = self.results.get("secrets", {})
        secret_list = secrets.get("hardcoded_secrets", [])
        
        if not secret_list:
            return """
            <div class="section">
                <h2>Hardcoded Secrets</h2>
                <div class="card">
                    <p style="text-align: center; color: #27ae60; font-size: 1.2em;">
                        ✅ No hardcoded secrets found
                    </p>
                </div>
            </div>
            """
        
        high_risk = [s for s in secret_list if s.get("risk_level") == "high"]
        medium_risk = [s for s in secret_list if s.get("risk_level") == "medium"]
        low_risk = [s for s in secret_list if s.get("risk_level") == "low"]
        
        return f"""
        <div class="section">
            <h2>Hardcoded Secrets</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>Secret Summary</h3>
                    <div class="stat">
                        <span class="stat-label">Total Secrets</span>
                        <span class="stat-value badge {'danger' if len(secret_list) > 0 else 'success'}">{len(secret_list)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">High Risk</span>
                        <span class="stat-value badge {'danger' if len(high_risk) > 0 else 'success'}">{len(high_risk)}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Medium Risk</span>
                        <span class="stat-value badge {'warning' if len(medium_risk) > 0 else 'success'}">{len(medium_risk)}</span>
                    </div>
                </div>
            </div>
            
            {self._generate_secrets_table(secret_list[:10])}
        </div>
        """
    
    def _generate_secrets_table(self, secrets):
        """Generate secrets table"""
        if not secrets:
            return ""
        
        table_html = '<h3>Detected Secrets</h3><table class="table"><thead><tr><th>Type</th><th>Risk Level</th><th>File</th></tr></thead><tbody>'
        
        for secret in secrets:
            secret_type = secret.get("type", "Unknown")
            risk_level = secret.get("risk_level", "Unknown")
            file_path = secret.get("file", "Unknown")
            
            risk_class = "danger" if risk_level == "high" else "warning" if risk_level == "medium" else "info"
            
            table_html += f"""
            <tr>
                <td>{html.escape(secret_type)}</td>
                <td><span class="badge {risk_class}">{risk_level.upper()}</span></td>
                <td style="font-family: monospace; font-size: 0.9em;">{html.escape(file_path)}</td>
            </tr>
            """
        
        table_html += '</tbody></table>'
        return table_html