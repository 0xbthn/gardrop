#!/usr/bin/env python3
"""
Report Generator
Generates comprehensive security analysis reports
"""

import json
import html
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self, analysis_results, output_dir):
        self.results = analysis_results
        self.output_dir = Path(output_dir)
        
    def generate_report(self):
        """Generate comprehensive security report"""
        try:
            # Generate JSON report
            self._generate_json_report()
            
            # Generate HTML report
            self._generate_html_report()
            
            # Generate text summary
            self._generate_text_summary()
            
            print(f"[+] Reports generated in: {self.output_dir}")
            
        except Exception as e:
            print(f"[-] Report generation error: {str(e)}")
    
    def _generate_json_report(self):
        """Generate detailed JSON report"""
        json_file = self.output_dir / "security_analysis.json"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self):
        """Generate HTML security report"""
        html_file = self.output_dir / "security_report.html"
        
        html_content = self._create_html_report()
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _create_html_report(self):
        """Create HTML report content with modern sidebar design"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Report</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        
        .app-container {{
            display: flex;
            min-height: 100vh;
        }}
        
        /* Sidebar Styles */
        .sidebar {{
            width: 280px;
            background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
            color: white;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            z-index: 1000;
        }}
        
        .sidebar-header {{
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #34495e;
            background: rgba(0,0,0,0.1);
        }}
        
        .sidebar-header h2 {{
            color: #ecf0f1;
            font-size: 18px;
            margin-bottom: 5px;
        }}
        
        .sidebar-header p {{
            color: #bdc3c7;
            font-size: 12px;
        }}
        
        .nav-menu {{
            padding: 20px 0;
        }}
        
        .nav-item {{
            padding: 12px 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .nav-item:hover {{
            background: rgba(52, 152, 219, 0.2);
            border-left-color: #3498db;
        }}
        
        .nav-item.active {{
            background: rgba(52, 152, 219, 0.3);
            border-left-color: #3498db;
        }}
        
        .nav-item i {{
            width: 20px;
            text-align: center;
        }}
        
        .nav-item span {{
            font-size: 14px;
            font-weight: 500;
        }}
        
        .nav-badge {{
            background: #e74c3c;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            margin-left: auto;
        }}
        
        /* Main Content */
        .main-content {{
            flex: 1;
            margin-left: 280px;
            padding: 20px;
        }}
        
        .content-section {{
            display: none;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .content-section.active {{
            display: block;
        }}
        
        .section-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            position: relative;
        }}
        
        .section-header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .section-header p {{
            opacity: 0.9;
            font-size: 14px;
        }}
        
        .section-content {{
            padding: 30px;
        }}
        
        /* Dashboard Cards */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border: 1px solid #e1e8ed;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}
        
        .card-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .card-icon {{
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            color: white;
        }}
        
        .card-icon.success {{
            background: linear-gradient(135deg, #00b894, #00cec9);
        }}
        
        .card-icon.warning {{
            background: linear-gradient(135deg, #fdcb6e, #e17055);
        }}
        
        .card-icon.danger {{
            background: linear-gradient(135deg, #e17055, #d63031);
        }}
        
        .card-icon.info {{
            background: linear-gradient(135deg, #74b9ff, #0984e3);
        }}
        
        .card-title {{
            font-size: 18px;
            font-weight: 600;
            color: #2d3436;
        }}
        
        .card-value {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .card-description {{
            color: #636e72;
            font-size: 14px;
        }}
        
        /* Vulnerability Cards */
        .vulnerability-card {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
            transition: transform 0.2s ease;
        }}
        
        .vulnerability-card:hover {{
            transform: translateX(5px);
        }}
        
        .vulnerability-card.high {{
            border-left-color: #e74c3c;
            background: linear-gradient(135deg, #fff5f5 0%, #ffe8e8 100%);
        }}
        
        .vulnerability-card.medium {{
            border-left-color: #f39c12;
            background: linear-gradient(135deg, #fffbf0 0%, #fff3e0 100%);
        }}
        
        .vulnerability-card.low {{
            border-left-color: #27ae60;
            background: linear-gradient(135deg, #f0fff4 0%, #e8f5e8 100%);
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vuln-title {{
            font-size: 16px;
            font-weight: 600;
            color: #2d3436;
        }}
        
        .vuln-risk {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .vuln-risk.high {{
            background: #e74c3c;
            color: white;
        }}
        
        .vuln-risk.medium {{
            background: #f39c12;
            color: white;
        }}
        
        .vuln-risk.low {{
            background: #27ae60;
            color: white;
        }}
        
        .vuln-description {{
            color: #636e72;
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        
        .vuln-details {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
        }}
        
        .vuln-details h4 {{
            color: #2d3436;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        
        .vuln-details p {{
            color: #636e72;
            font-size: 13px;
            margin-bottom: 5px;
        }}
        
        /* Tables */
        .table-container {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e1e8ed;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        /* Progress Bars */
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: #e1e8ed;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        
        .progress-fill.high {{
            background: linear-gradient(90deg, #e74c3c, #c0392b);
        }}
        
        .progress-fill.medium {{
            background: linear-gradient(90deg, #f39c12, #e67e22);
        }}
        
        .progress-fill.low {{
            background: linear-gradient(90deg, #27ae60, #2ecc71);
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .sidebar {{
                transform: translateX(-100%);
                transition: transform 0.3s ease;
            }}
            
            .sidebar.open {{
                transform: translateX(0);
            }}
            
            .main-content {{
                margin-left: 0;
            }}
            
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        /* Animations */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .content-section.active {{
            animation: fadeIn 0.5s ease;
        }}
        
        /* Code blocks */
        .code-block {{
            background: #2d3436;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        /* Permissions */
        .permission-tag {{
            display: inline-block;
            padding: 4px 12px;
            margin: 3px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
        }}
        
        .permission-tag.dangerous {{
            background: #e74c3c;
            color: white;
        }}
        
        .permission-tag.normal {{
            background: #3498db;
            color: white;
        }}
        
        .permission-tag.signature {{
            background: #9b59b6;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">
                <h2><i class="fas fa-shield-alt"></i> Security Report</h2>
                <p>APK Analysis Dashboard</p>
            </div>
            
            <div class="nav-menu">
                <div class="nav-item active" onclick="showSection('dashboard')">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </div>
                
                <div class="nav-item" onclick="showSection('overview')">
                    <i class="fas fa-chart-pie"></i>
                    <span>Overview</span>
                </div>
                
                <div class="nav-item" onclick="showSection('vulnerabilities')">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Vulnerabilities</span>
                    <span class="nav-badge" id="vuln-count">0</span>
                </div>
                
                <div class="nav-item" onclick="showSection('permissions')">
                    <i class="fas fa-key"></i>
                    <span>Permissions</span>
                </div>
                
                <div class="nav-item" onclick="showSection('secrets')">
                    <i class="fas fa-user-secret"></i>
                    <span>Secrets</span>
                    <span class="nav-badge" id="secrets-count">0</span>
                </div>
                
                <div class="nav-item" onclick="showSection('manifest')">
                    <i class="fas fa-file-code"></i>
                    <span>Manifest</span>
                </div>
                
                <div class="nav-item" onclick="showSection('structure')">
                    <i class="fas fa-folder-tree"></i>
                    <span>Structure</span>
                </div>
                
                <div class="nav-item" onclick="showSection('certificates')">
                    <i class="fas fa-certificate"></i>
                    <span>Certificates</span>
                </div>
                
                <div class="nav-item" onclick="showSection('network')">
                    <i class="fas fa-network-wired"></i>
                    <span>Network</span>
                </div>
                
                <div class="nav-item" onclick="showSection('internet')">
                    <i class="fas fa-globe"></i>
                    <span>Internet Artifacts</span>
                </div>
                
                <div class="nav-item" onclick="showSection('recommendations')">
                    <i class="fas fa-lightbulb"></i>
                    <span>Recommendations</span>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <!-- Dashboard Section -->
            <div id="dashboard" class="content-section active">
                <div class="section-header">
                    <h1><i class="fas fa-tachometer-alt"></i> Security Dashboard</h1>
                    <p>Comprehensive overview of APK security analysis</p>
                </div>
                <div class="section-content">
                    {self._generate_dashboard_content()}
                </div>
            </div>
            
            <!-- Overview Section -->
            <div id="overview" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-chart-pie"></i> Executive Summary</h1>
                    <p>High-level security assessment and key findings</p>
                </div>
                <div class="section-content">
                    {self._generate_executive_summary()}
                </div>
            </div>
            
            <!-- Vulnerabilities Section -->
            <div id="vulnerabilities" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-exclamation-triangle"></i> Security Vulnerabilities</h1>
                    <p>Detailed analysis of discovered security issues</p>
                </div>
                <div class="section-content">
                    {self._generate_vulnerabilities_section()}
                </div>
            </div>
            
            <!-- Permissions Section -->
            <div id="permissions" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-key"></i> Permissions Analysis</h1>
                    <p>Android permissions and their security implications</p>
                </div>
                <div class="section-content">
                    {self._generate_permissions_section()}
                </div>
            </div>
            
            <!-- Secrets Section -->
            <div id="secrets" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-user-secret"></i> Secrets Detection</h1>
                    <p>Hardcoded secrets and sensitive information found</p>
                </div>
                <div class="section-content">
                    {self._generate_secrets_section()}
                </div>
            </div>
            
            <!-- Manifest Section -->
            <div id="manifest" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-file-code"></i> Manifest Analysis</h1>
                    <p>AndroidManifest.xml configuration and security settings</p>
                </div>
                <div class="section-content">
                    {self._generate_manifest_section()}
                </div>
            </div>
            
            <!-- Structure Section -->
            <div id="structure" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-folder-tree"></i> APK Structure</h1>
                    <p>Application structure and file organization</p>
                </div>
                <div class="section-content">
                    {self._generate_structure_section()}
                </div>
            </div>
            
            <!-- Certificates Section -->
            <div id="certificates" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-certificate"></i> Certificate Analysis</h1>
                    <p>Code signing certificates and trust verification</p>
                </div>
                <div class="section-content">
                    {self._generate_certificates_section()}
                </div>
            </div>
            
            <!-- Network Section -->
            <div id="network" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-network-wired"></i> Network Security</h1>
                    <p>Network configuration and communication security</p>
                </div>
                <div class="section-content">
                    {self._generate_network_section()}
                </div>
            </div>
            
            <!-- Internet Artifacts Section -->
            <div id="internet" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-globe"></i> Internet Artifacts</h1>
                    <p>URLs, emails, hashes, and network artifacts analysis</p>
                </div>
                <div class="section-content">
                    {self._generate_internet_section()}
                </div>
            </div>
            
            <!-- Recommendations Section -->
            <div id="recommendations" class="content-section">
                <div class="section-header">
                    <h1><i class="fas fa-lightbulb"></i> Security Recommendations</h1>
                    <p>Actionable recommendations to improve security</p>
                </div>
                <div class="section-content">
                    {self._generate_recommendations_section()}
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Navigation functionality
        function showSection(sectionId) {{
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(section => {{
                section.classList.remove('active');
            }});
            
            // Remove active class from all nav items
            document.querySelectorAll('.nav-item').forEach(item => {{
                item.classList.remove('active');
            }});
            
            // Show selected section
            document.getElementById(sectionId).classList.add('active');
            
            // Add active class to clicked nav item
            event.currentTarget.classList.add('active');
        }}
        
        // Update badge counts
        document.addEventListener('DOMContentLoaded', function() {{
            const vulnCount = document.querySelectorAll('.vulnerability-card').length;
            const secretsCount = document.querySelectorAll('.secret-item').length;
            
            document.getElementById('vuln-count').textContent = vulnCount;
            document.getElementById('secrets-count').textContent = secretsCount;
        }});
        
        // Mobile menu toggle
        function toggleSidebar() {{
            document.querySelector('.sidebar').classList.toggle('open');
        }}
    </script>
</body>
</html>
"""
        return html_content
    
    def _generate_executive_summary(self):
        """Generate executive summary section"""
        security = self.results.get('security', {})
        score = security.get('security_score', 0)
        score_class = 'high' if score >= 70 else 'medium' if score >= 40 else 'low'
        
        manifest = self.results.get('manifest', {})
        package_name = manifest.get('package_name', 'Unknown')
        
        vulns = security.get('vulnerability_summary', [])
        high_vulns = len([v for v in vulns if v.get('risk', '').lower() == 'high'])
        medium_vulns = len([v for v in vulns if v.get('risk', '').lower() == 'medium'])
        
        return f"""
        <div class="summary">
            <h2>Executive Summary</h2>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div class="metric">
                    <div>Security Score</div>
                    <div class="score {score_class}">{score}/100</div>
                </div>
                <div class="metric">
                    <div>Package Name</div>
                    <div class="code">{html.escape(package_name)}</div>
                </div>
                <div class="metric">
                    <div>High Risk Issues</div>
                    <div class="risk-high">{high_vulns}</div>
                </div>
                <div class="metric">
                    <div>Medium Risk Issues</div>
                    <div class="risk-medium">{medium_vulns}</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_structure_section(self):
        """Generate APK structure section"""
        structure = self.results.get('structure', {})
        
        return f"""
        <div class="section">
            <h2>APK Structure Analysis</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>File Exists</td><td><i class="fas fa-check" style="color: #27ae60;"></i> Yes</td></tr>
        <tr><td>File Readable</td><td><i class="fas fa-check" style="color: #27ae60;"></i> Yes</td></tr>
        <tr><td>Valid ZIP</td><td><i class="fas fa-check" style="color: #27ae60;"></i> Yes</td></tr>
        <tr><td>Can Extract</td><td><i class="fas fa-check" style="color: #27ae60;"></i> Yes</td></tr>
                <tr><td>File Size</td><td>{structure.get('file_size', 0):,} bytes</td></tr>
                <tr><td>Total Files</td><td>{len(structure.get('contents', []))}</td></tr>
            </table>
            
            <h3>Structure Components</h3>
            <ul>
                            <li>AndroidManifest.xml: <i class="fas fa-check" style="color: #27ae60;"></i> Yes</li>
            <li>DEX Files: <i class="fas fa-check" style="color: #27ae60;"></i> Yes ({len(structure.get('structure', {}).get('dex_files', []))} files)</li>
            <li>Resources: <i class="fas fa-check" style="color: #27ae60;"></i> Yes</li>
            <li>Assets: <i class="fas fa-check" style="color: #27ae60;"></i> Yes</li>
            <li>Native Libraries: <i class="fas fa-check" style="color: #27ae60;"></i> Yes</li>
            </ul>
        </div>
        """
    
    def _generate_manifest_section(self):
        """Generate comprehensive manifest analysis section"""
        manifest = self.results.get('manifest', {})
        
        exported_components = manifest.get('exported_components', {})
        total_exported = (len(exported_components.get('activities', [])) + 
                         len(exported_components.get('services', [])) + 
                         len(exported_components.get('receivers', [])) + 
                         len(exported_components.get('providers', [])))
        
        manifest_html = """
        <div class="section">
            <h2><i class="fas fa-mobile-alt"></i> AndroidManifest.xml Analysis</h2>
        """
        
        # Basic information
        manifest_html += f"""
        <h3>📋 Basic Information</h3>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Package Name</td><td class="code">{html.escape(manifest.get('package_name', 'Unknown'))}</td></tr>
            <tr><td>Version Code</td><td>{manifest.get('version_code', 'Unknown')}</td></tr>
            <tr><td>Version Name</td><td>{manifest.get('version_name', 'Unknown')}</td></tr>
            <tr><td>Min SDK</td><td>{manifest.get('min_sdk', 'Unknown')}</td></tr>
            <tr><td>Target SDK</td><td>{manifest.get('target_sdk', 'Unknown')}</td></tr>
            <tr><td>Compile SDK</td><td>{manifest.get('compile_sdk', 'Unknown')}</td></tr>
        </table>
        """
        
        # Security flags with detailed analysis
        security_flags = manifest.get('security_flags', {})
        manifest_html += f"""
        <h3>🔒 Security Flags Analysis</h3>
        <table>
            <tr><th>Flag</th><th>Value</th><th>Risk Level</th><th>Description</th></tr>
            <tr><td>Debuggable</td><td>{'❌ TRUE' if security_flags.get('debuggable') else '✅ FALSE'}</td><td><span class="risk-high">HIGH</span></td><td>Application can be debugged in production</td></tr>
            <tr><td>Allow Backup</td><td>{'⚠️ TRUE' if security_flags.get('allow_backup') else '✅ FALSE'}</td><td><span class="risk-medium">MEDIUM</span></td><td>Application data can be backed up</td></tr>
            <tr><td>Cleartext Traffic</td><td>{'❌ TRUE' if security_flags.get('uses_cleartext_traffic') else '✅ FALSE'}</td><td><span class="risk-high">HIGH</span></td><td>Application can use HTTP instead of HTTPS</td></tr>
            <tr><td>Network Security Config</td><td>{html.escape(security_flags.get('network_security_config', 'Not specified'))}</td><td><span class="risk-low">LOW</span></td><td>Custom network security configuration</td></tr>
        </table>
        """
        
        # Permissions analysis
        permissions = manifest.get('permissions', [])
        dangerous_permissions = manifest.get('dangerous_permissions', [])
        
        manifest_html += f"""
        <h3>🔐 Permissions Analysis</h3>
        <div class="summary">
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div class="metric">
                    <div>Total Permissions</div>
                    <div class="risk-low">{len(permissions)}</div>
                </div>
                <div class="metric">
                    <div>Dangerous Permissions</div>
                    <div class="risk-high">{len(dangerous_permissions)}</div>
                </div>
                <div class="metric">
                    <div>Normal Permissions</div>
                    <div class="risk-low">{len(permissions) - len(dangerous_permissions)}</div>
                </div>
            </div>
        </div>
        """
        
        if dangerous_permissions:
            manifest_html += "<h4>🚨 Dangerous Permissions</h4><div>"
            for perm in dangerous_permissions:
                manifest_html += f'<span class="permission dangerous">{html.escape(perm)}</span>'
            manifest_html += "</div>"
        
        if permissions:
            manifest_html += "<h4>📋 All Permissions</h4><div>"
            for perm in permissions:
                is_dangerous = perm in dangerous_permissions
                perm_class = "dangerous" if is_dangerous else "normal"
                manifest_html += f'<span class="permission {perm_class}">{html.escape(perm)}</span>'
            manifest_html += "</div>"
        
        # Exported components analysis
        manifest_html += f"""
        <h3>🚪 Exported Components Analysis</h3>
        <div class="summary">
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div class="metric">
                    <div>Total Exported</div>
                    <div class="risk-high">{total_exported}</div>
                </div>
                <div class="metric">
                    <div>Activities</div>
                    <div class="risk-medium">{len(exported_components.get('activities', []))}</div>
                </div>
                <div class="metric">
                    <div>Services</div>
                    <div class="risk-medium">{len(exported_components.get('services', []))}</div>
                </div>
                <div class="metric">
                    <div>Receivers</div>
                    <div class="risk-medium">{len(exported_components.get('receivers', []))}</div>
                </div>
                <div class="metric">
                    <div>Providers</div>
                    <div class="risk-high">{len(exported_components.get('providers', []))}</div>
                </div>
            </div>
        </div>
        """
        
        # Detailed exported components
        for component_type, components in exported_components.items():
            if components:
                manifest_html += f"<h4>🔍 {component_type.title()} ({len(components)})</h4>"
                for component in components:
                    risk_level = component.get('risk_level', 'low')
                    risk_class = 'high' if risk_level == 'high' else 'medium' if risk_level == 'medium' else 'low'
                    
                    manifest_html += f"""
                    <div class="vulnerability {risk_class}">
                        <table style="width: 100%; margin: 10px 0;">
                            <tr><td><strong>Name:</strong></td><td class="code">{html.escape(component.get('name', 'Unknown'))}</td></tr>
                            <tr><td><strong>Exported:</strong></td><td>{'✅ Yes' if component.get('exported') else '❌ No'}</td></tr>
                            <tr><td><strong>Auto-exported:</strong></td><td>{'⚠️ Yes' if component.get('auto_exported') else '❌ No'}</td></tr>
                            <tr><td><strong>Has Intent Filter:</strong></td><td>{'✅ Yes' if component.get('has_intent_filter') else '❌ No'}</td></tr>
                            <tr><td><strong>Risk Level:</strong></td><td><span class="risk-{risk_class}">{risk_level.upper()}</span></td></tr>
                        </table>
                    </div>
                    """
        
        # Intent filters
        intent_filters = manifest.get('intent_filters', [])
        if intent_filters:
            manifest_html += f"<h3>🎯 Intent Filters ({len(intent_filters)})</h3>"
            for i, intent_filter in enumerate(intent_filters[:10]):  # Limit to first 10
                manifest_html += f"""
                <div class="vulnerability medium">
                    <h4>Intent Filter #{i+1}</h4>
                    <table style="width: 100%; margin: 10px 0;">
                        <tr><td><strong>Actions:</strong></td><td>{', '.join(html.escape(action) for action in intent_filter.get('actions', []))}</td></tr>
                        <tr><td><strong>Categories:</strong></td><td>{', '.join(html.escape(cat) for cat in intent_filter.get('categories', []))}</td></tr>
                        <tr><td><strong>Data:</strong></td><td>{', '.join(str(data) for data in intent_filter.get('data', []))}</td></tr>
                    </table>
                </div>
                """
        
        # Meta data
        meta_data = manifest.get('meta_data', [])
        if meta_data:
            manifest_html += f"<h3>📄 Meta Data ({len(meta_data)})</h3>"
            for meta in meta_data[:10]:  # Limit to first 10
                manifest_html += f"""
                <div class="vulnerability low">
                    <strong>Name:</strong> {html.escape(meta.get('name', 'Unknown'))}<br>
                    <strong>Value:</strong> {html.escape(str(meta.get('value', 'Unknown')))}
                </div>
                """
        
        manifest_html += "</div>"
        return manifest_html
    
    def _generate_dex_section(self):
        """Generate comprehensive DEX analysis section"""
        dex = self.results.get('dex', {})
        
        dex_html = """
        <div class="section">
            <h2>📦 DEX Code Analysis</h2>
        """
        
        # Basic statistics
        total_classes = len(dex.get('classes', []))
        total_methods = len(dex.get('methods', []))
        total_strings = len(dex.get('strings', []))
        total_packages = len(dex.get('packages', []))
        
        dex_html += f"""
        <div class="summary">
            <h3>📊 DEX Statistics</h3>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div class="metric">
                    <div>Total Classes</div>
                    <div class="risk-low">{total_classes}</div>
                </div>
                <div class="metric">
                    <div>Total Methods</div>
                    <div class="risk-low">{total_methods}</div>
                </div>
                <div class="metric">
                    <div>Total Strings</div>
                    <div class="risk-low">{total_strings}</div>
                </div>
                <div class="metric">
                    <div>Total Packages</div>
                    <div class="risk-low">{total_packages}</div>
                </div>
            </div>
        </div>
        """
        
        # Obfuscation analysis
        obfuscation_detected = dex.get('obfuscation_detected', False)
        obfuscation_ratio = dex.get('obfuscation_ratio', 0)
        
        dex_html += f"""
        <h3>🔒 Code Protection Analysis</h3>
        <table>
            <tr><th>Property</th><th>Value</th><th>Risk Level</th></tr>
            <tr><td>Obfuscation Detected</td><td>{'❌ YES' if obfuscation_detected else '✅ NO'}</td><td><span class="risk-high">HIGH</span></td></tr>
            <tr><td>Obfuscation Ratio</td><td>{obfuscation_ratio:.2%}</td><td><span class="risk-medium">MEDIUM</span></td></tr>
            <tr><td>ProGuard/R8 Usage</td><td>{'✅ Detected' if any('proguard' in pkg.lower() or 'r8' in pkg.lower() for pkg in dex.get('packages', [])) else '❌ Not Detected'}</td><td><span class="risk-low">LOW</span></td></tr>
        </table>
        """
        
        # Package analysis
        packages = dex.get('packages', [])
        if packages:
            dex_html += f"<h3>📁 Package Analysis ({len(packages)} packages)</h3>"
            
            # Group packages by risk level
            high_risk_packages = []
            medium_risk_packages = []
            low_risk_packages = []
            
            for pkg in packages:
                pkg_lower = pkg.lower()
                if any(risk in pkg_lower for risk in ['webview', 'http', 'sql', 'crypto', 'ssl', 'tls']):
                    high_risk_packages.append(pkg)
                elif any(risk in pkg_lower for risk in ['network', 'file', 'storage', 'permission']):
                    medium_risk_packages.append(pkg)
                else:
                    low_risk_packages.append(pkg)
            
            if high_risk_packages:
                dex_html += "<h4>🚨 High-Risk Packages</h4><div>"
                for pkg in high_risk_packages[:20]:  # Limit display
                    dex_html += f'<span class="permission dangerous">{html.escape(pkg)}</span>'
                dex_html += "</div>"
            
            if medium_risk_packages:
                dex_html += "<h4>⚠️ Medium-Risk Packages</h4><div>"
                for pkg in medium_risk_packages[:20]:  # Limit display
                    dex_html += f'<span class="permission medium">{html.escape(pkg)}</span>'
                dex_html += "</div>"
            
            if low_risk_packages:
                dex_html += "<h4>✅ Low-Risk Packages</h4><div>"
                for pkg in low_risk_packages[:20]:  # Limit display
                    dex_html += f'<span class="permission normal">{html.escape(pkg)}</span>'
                dex_html += "</div>"
        
        # String analysis
        strings = dex.get('strings', [])
        if strings:
            dex_html += f"<h3>📝 String Analysis ({len(strings)} strings)</h3>"
            
            # Find interesting strings
            interesting_strings = []
            for string in strings:
                string_lower = string.lower()
                if any(pattern in string_lower for pattern in [
                    'http://', 'https://', 'api', 'key', 'password', 'token', 'secret',
                    'admin', 'root', 'debug', 'test', 'localhost', '127.0.0.1'
                ]):
                    interesting_strings.append(string)
            
            if interesting_strings:
                dex_html += "<h4>🔍 Interesting Strings</h4>"
                for string in interesting_strings[:50]:  # Limit display
                    dex_html += f"""
                    <div class="vulnerability medium">
                        <code>{html.escape(string)}</code>
                    </div>
                    """
        
        # Class analysis
        classes = dex.get('classes', [])
        if classes:
            dex_html += f"<h3>🏗️ Class Analysis ({len(classes)} classes)</h3>"
            
            # Find interesting classes
            interesting_classes = []
            for cls in classes:
                cls_lower = str(cls).lower()
                if any(pattern in cls_lower for pattern in [
                    'webview', 'http', 'sql', 'crypto', 'ssl', 'tls', 'network',
                    'file', 'storage', 'permission', 'activity', 'service'
                ]):
                    interesting_classes.append(cls)
            
            if interesting_classes:
                dex_html += "<h4>🔍 Interesting Classes</h4>"
                for cls in interesting_classes[:30]:  # Limit display
                    dex_html += f"""
                    <div class="vulnerability low">
                        <code>{html.escape(str(cls))}</code>
                    </div>
                    """
        
        # Method analysis
        methods = dex.get('methods', [])
        if methods:
            dex_html += f"<h3>⚙️ Method Analysis ({len(methods)} methods)</h3>"
            
            # Find interesting methods
            interesting_methods = []
            for method in methods:
                method_lower = str(method).lower()
                if any(pattern in method_lower for pattern in [
                    'http', 'sql', 'crypto', 'ssl', 'tls', 'network', 'file',
                    'storage', 'permission', 'webview', 'javascript'
                ]):
                    interesting_methods.append(method)
            
            if interesting_methods:
                dex_html += "<h4>🔍 Interesting Methods</h4>"
                for method in interesting_methods[:30]:  # Limit display
                    dex_html += f"""
                    <div class="vulnerability low">
                        <code>{html.escape(str(method))}</code>
                    </div>
                    """
        
        dex_html += "</div>"
        return dex_html
    
    def _generate_dashboard_content(self):
        """Generate dashboard content with key metrics"""
        security = self.results.get("security", {})
        security_score = security.get("security_score", 0)
        
        # Count vulnerabilities by severity
        all_vulns = security.get("vulnerability_summary", [])
        high_vulns = len([v for v in all_vulns if v.get("risk") == "Critical" or v.get("risk") == "High"])
        medium_vulns = len([v for v in all_vulns if v.get("risk") == "Medium"])
        low_vulns = len([v for v in all_vulns if v.get("risk") == "Low"])
        
        # Get other metrics
        secrets = self.results.get("secrets", {})
        secrets_count = len(secrets.get("hardcoded_secrets", []))
        
        permissions = self.results.get("permissions", {})
        dangerous_perms = len([p for p in permissions.get("permissions", []) 
                             if isinstance(p, dict) and p.get("protection_level") == "dangerous"])
        
        manifest = self.results.get("manifest", {})
        exported_components = manifest.get("exported_components", {})
        total_exported = (len(exported_components.get("activities", [])) + 
                         len(exported_components.get("services", [])) + 
                         len(exported_components.get("broadcast_receivers", [])) + 
                         len(exported_components.get("content_providers", [])))
        
        # Determine score color
        score_color = "success" if security_score >= 70 else "warning" if security_score >= 40 else "danger"
        
        dashboard_html = f"""
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon {score_color}">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div>
                        <div class="card-title">Security Score</div>
                        <div class="card-value">{security_score}/100</div>
                        <div class="card-description">Overall security assessment</div>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill {score_color}" style="width: {security_score}%"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon danger">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div>
                        <div class="card-title">High Risk Issues</div>
                        <div class="card-value">{high_vulns}</div>
                        <div class="card-description">Critical & High severity vulnerabilities</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div>
                        <div class="card-title">Medium Risk Issues</div>
                        <div class="card-value">{medium_vulns}</div>
                        <div class="card-description">Medium severity vulnerabilities</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-user-secret"></i>
                    </div>
                    <div>
                        <div class="card-title">Hardcoded Secrets</div>
                        <div class="card-value">{secrets_count}</div>
                        <div class="card-description">Sensitive data found in code</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-key"></i>
                    </div>
                    <div>
                        <div class="card-title">Dangerous Permissions</div>
                        <div class="card-value">{dangerous_perms}</div>
                        <div class="card-description">High-risk permissions requested</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-external-link-alt"></i>
                    </div>
                    <div>
                        <div class="card-title">Exported Components</div>
                        <div class="card-value">{total_exported}</div>
                        <div class="card-description">Components accessible by other apps</div>
                    </div>
                </div>
            </div>
        """
        
        # Internet artifacts section
        internet = self.results.get("internet", {})
        if internet:
            total_urls = internet.get("statistics", {}).get("total_urls", 0)
            total_emails = internet.get("statistics", {}).get("total_emails", 0)
            total_endpoints = internet.get("statistics", {}).get("total_endpoints", 0)
            
            dashboard_html += f"""
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-globe"></i>
                    </div>
                    <div>
                        <div class="card-title">Internet Artifacts</div>
                        <div class="card-value">{total_urls + total_emails + total_endpoints}</div>
                        <div class="card-description">URLs, emails, and endpoints found</div>
                    </div>
                </div>
            </div>
            """
        
        dashboard_html += """
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-icon info">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div class="card-title">Quick Actions</div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <button onclick="showSection('vulnerabilities')" style="padding: 12px; background: #e74c3c; color: white; border: none; border-radius: 8px; cursor: pointer;">
                    <i class="fas fa-exclamation-triangle"></i> View Vulnerabilities
                </button>
                <button onclick="showSection('secrets')" style="padding: 12px; background: #f39c12; color: white; border: none; border-radius: 8px; cursor: pointer;">
                    <i class="fas fa-user-secret"></i> View Secrets
                </button>
                <button onclick="showSection('permissions')" style="padding: 12px; background: #3498db; color: white; border: none; border-radius: 8px; cursor: pointer;">
                    <i class="fas fa-key"></i> View Permissions
                </button>
                <button onclick="showSection('internet')" style="padding: 12px; background: #9b59b6; color: white; border: none; border-radius: 8px; cursor: pointer;">
                    <i class="fas fa-globe"></i> View Internet Artifacts
                </button>
                <button onclick="showSection('recommendations')" style="padding: 12px; background: #27ae60; color: white; border: none; border-radius: 8px; cursor: pointer;">
                    <i class="fas fa-lightbulb"></i> View Recommendations
                </button>
            </div>
        </div>
        """
        
        return dashboard_html
    
    def _generate_vulnerabilities_section(self):
        """Generate vulnerabilities section with modern cards"""
        security = self.results.get("security", {})
        vulnerabilities = security.get("vulnerability_summary", [])
        
        if not vulnerabilities:
            return """
            <div class="card">
                <div class="card-header">
                    <div class="card-icon success">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="card-title">No Vulnerabilities Found</div>
                </div>
                <p>Great! No security vulnerabilities were detected in this APK.</p>
            </div>
            """
        
        vuln_html = ""
        
        # Group by risk level
        high_vulns = [v for v in vulnerabilities if v.get("risk") in ["Critical", "High"]]
        medium_vulns = [v for v in vulnerabilities if v.get("risk") == "Medium"]
        low_vulns = [v for v in vulnerabilities if v.get("risk") == "Low"]
        
        # High risk vulnerabilities
        if high_vulns:
            vuln_html += "<h3 style='color: #e74c3c; margin-bottom: 20px;'><i class='fas fa-exclamation-triangle'></i> High Risk Vulnerabilities</h3>"
            for vuln in high_vulns:
                vuln_html += self._create_vulnerability_card(vuln, "high")
        
        # Medium risk vulnerabilities
        if medium_vulns:
            vuln_html += "<h3 style='color: #f39c12; margin: 20px 0;'><i class='fas fa-exclamation-circle'></i> Medium Risk Vulnerabilities</h3>"
            for vuln in medium_vulns:
                vuln_html += self._create_vulnerability_card(vuln, "medium")
        
        # Low risk vulnerabilities
        if low_vulns:
            vuln_html += "<h3 style='color: #27ae60; margin: 20px 0;'><i class='fas fa-info-circle'></i> Low Risk Vulnerabilities</h3>"
            for vuln in low_vulns:
                vuln_html += self._create_vulnerability_card(vuln, "low")
        
        return vuln_html
    
    def _create_vulnerability_card(self, vuln, risk_level):
        """Create a modern vulnerability card"""
        risk_class = "high" if risk_level == "high" else "medium" if risk_level == "medium" else "low"
        
        card_html = f"""
        <div class="vulnerability-card {risk_class}">
            <div class="vuln-header">
                <div class="vuln-title">{html.escape(vuln.get("type", "Unknown Vulnerability"))}</div>
                <div class="vuln-risk {risk_class}">{vuln.get("risk", "Unknown")}</div>
            </div>
            
            <div class="vuln-description">{html.escape(vuln.get("description", "No description available"))}</div>
            
            <div class="vuln-details">
                <h4><i class="fas fa-info-circle"></i> Details</h4>
                <p><strong>Category:</strong> {html.escape(vuln.get("category", "Unknown"))}</p>
                <p><strong>Impact:</strong> {html.escape(vuln.get("impact", "Unknown"))}</p>
                <p><strong>File:</strong> {html.escape(vuln.get("file", "Unknown"))}</p>
                <p><strong>Line:</strong> {html.escape(str(vuln.get("line", "N/A")))}</p>
                <p><strong>Class:</strong> {html.escape(vuln.get("class", "Unknown"))}</p>
                <p><strong>Method:</strong> {html.escape(vuln.get("method", "Unknown"))}</p>
                <p><strong>Detection Method:</strong> {html.escape(vuln.get("detection_method", "Unknown"))}</p>
                <p><strong>Remediation:</strong> {html.escape(vuln.get("remediation", "No remediation provided"))}</p>
            </div>
        </div>
        """
        
        return card_html
    
    def _generate_certificates_section(self):
        """Generate certificates section"""
        certificates = self.results.get("certificates", {})
        
        if not certificates:
            return """
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="card-title">No Certificate Information</div>
                </div>
                <p>Certificate analysis was not performed or no certificates were found.</p>
            </div>
            """
        
        cert_html = f"""
        <div class="card">
            <div class="card-header">
                <div class="card-icon info">
                    <i class="fas fa-certificate"></i>
                </div>
                <div class="card-title">Certificate Analysis</div>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for key, value in certificates.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    cert_html += f"""
                        <tr>
                            <td><strong>{html.escape(str(sub_key))}</strong></td>
                            <td>{html.escape(str(sub_value))}</td>
                        </tr>
                    """
            else:
                cert_html += f"""
                    <tr>
                        <td><strong>{html.escape(str(key))}</strong></td>
                        <td>{html.escape(str(value))}</td>
                    </tr>
                """
        
        cert_html += """
                    </tbody>
                </table>
            </div>
        </div>
        """
        
        return cert_html
    
    def _generate_network_section(self):
        """Generate network security section"""
        network = self.results.get("network", {})
        
        if not network:
            return """
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="card-title">No Network Information</div>
                </div>
                <p>Network analysis was not performed or no network configuration was found.</p>
            </div>
            """
        
        network_html = f"""
        <div class="card">
            <div class="card-header">
                <div class="card-icon info">
                    <i class="fas fa-network-wired"></i>
                </div>
                <div class="card-title">Network Security Analysis</div>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for key, value in network.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    network_html += f"""
                        <tr>
                            <td><strong>{html.escape(str(sub_key))}</strong></td>
                            <td>{html.escape(str(sub_value))}</td>
                        </tr>
                    """
            else:
                network_html += f"""
                    <tr>
                        <td><strong>{html.escape(str(key))}</strong></td>
                        <td>{html.escape(str(value))}</td>
                    </tr>
                """
        
        network_html += """
                    </tbody>
                </table>
            </div>
        </div>
        """
        
        return network_html
    
    def _generate_recommendations_section(self):
        """Generate security recommendations section"""
        security = self.results.get("security", {})
        recommendations = security.get("recommendations", [])
        
        if not recommendations:
            return """
            <div class="card">
                <div class="card-header">
                    <div class="card-icon success">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="card-title">No Specific Recommendations</div>
                </div>
                <p>No specific recommendations are available at this time.</p>
            </div>
            """
        
        rec_html = "<div class='dashboard-grid'>"
        
        for i, rec in enumerate(recommendations):
            rec_html = f"""
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-lightbulb"></i>
                    </div>
                    <div class="card-title">Recommendation {i+1}</div>
                </div>
                <p><strong>Category:</strong> {html.escape(rec.get('category', 'General'))}</p>
                <p><strong>Priority:</strong> {html.escape(rec.get('priority', 'Medium'))}</p>
                <p><strong>Description:</strong> {html.escape(rec.get('description', 'No description'))}</p>
                <p><strong>Action:</strong> {html.escape(rec.get('action', 'No action specified'))}</p>
            </div>
            """
            rec_html += rec_html
        
        rec_html += "</div>"
        
        return rec_html
    
    def _generate_permissions_section(self):
        """Generate permissions analysis section with modern design"""
        permissions = self.results.get('permissions', {})
        manifest = self.results.get('manifest', {})
        
        # Risk assessment
        risk_assessment = permissions.get('risk_assessment', {})
        overall_risk = risk_assessment.get('overall_risk', 'unknown')
        risk_score = risk_assessment.get('risk_score', 0)
        
        # Count permissions by protection level
        all_permissions = permissions.get('permissions', [])
        dangerous_perms = [p for p in all_permissions if isinstance(p, dict) and p.get('protection_level') == 'dangerous']
        normal_perms = [p for p in all_permissions if isinstance(p, dict) and p.get('protection_level') == 'normal']
        signature_perms = [p for p in all_permissions if isinstance(p, dict) and p.get('protection_level') == 'signature']
        
        permission_html = f"""
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon {'danger' if overall_risk == 'high' else 'warning' if overall_risk == 'medium' else 'success'}">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div>
                        <div class="card-title">Overall Risk</div>
                        <div class="card-value">{overall_risk.upper()}</div>
                        <div class="card-description">Permission security assessment</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon danger">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div>
                        <div class="card-title">Dangerous Permissions</div>
                        <div class="card-value">{len(dangerous_perms)}</div>
                        <div class="card-description">High-risk permissions requested</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-key"></i>
                    </div>
                    <div>
                        <div class="card-title">Normal Permissions</div>
                        <div class="card-value">{len(normal_perms)}</div>
                        <div class="card-description">Standard permissions requested</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-certificate"></i>
                    </div>
                    <div>
                        <div class="card-title">Signature Permissions</div>
                        <div class="card-value">{len(signature_perms)}</div>
                        <div class="card-description">System-level permissions</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-icon info">
                    <i class="fas fa-list"></i>
                </div>
                <div class="card-title">Permission Details</div>
            </div>
        """
        
        # Dangerous permissions
        dangerous_perms = manifest.get('dangerous_permissions', [])
        if dangerous_perms:
            permission_html += "<h3>Dangerous Permissions</h3><div>"
            for perm in dangerous_perms:
                permission_html += f'<span class="permission dangerous">{html.escape(perm)}</span>'
            permission_html += "</div>"
        
        # Permission combinations
        combinations = permissions.get('permission_combinations', [])
        if combinations:
            permission_html += "<h3><i class='fas fa-exclamation-triangle'></i> Risky Permission Combinations</h3>"
            for combo in combinations:
                severity_class = combo.get('severity', 'medium')
                permission_html += f'<div class="vulnerability {severity_class}"><strong>{combo.get("name", "Unknown")}</strong><br>Risk: {combo.get("risk", "Unknown")}<br>Severity: <span class="risk-{severity_class}">{severity_class.upper()}</span></div>'
        
        permission_html += "</div>"
        return permission_html
    
    def _generate_internet_section(self):
        """Generate internet artifacts section"""
        internet = self.results.get("internet", {})
        
        if not internet:
            return '''
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-globe"></i>
                    </div>
                    <div>
                        <div class="card-title">No Internet Information</div>
                        <div class="card-description">Internet analysis was not performed.</div>
                    </div>
                </div>
            </div>
            '''
        
        # Use SimpleInternetReporter
        try:
            from modules.simple_internet_reporter import SimpleInternetReporter
            reporter = SimpleInternetReporter(internet)
            return reporter.generate_html_section()
        except:
            return '''
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div>
                        <div class="card-title">Internet Analysis Error</div>
                        <div class="card-description">Could not generate internet artifacts report.</div>
                    </div>
                </div>
            </div>
            '''
    
    def _generate_security_section(self):
        """Generate security analysis section"""
        security = self.results.get('security', {})
        
        obfuscation_detected = security.get('obfuscation_analysis', {}).get('detected', False)
        debug_enabled = security.get('debug_analysis', {}).get('debuggable', False)
        cleartext_allowed = security.get('network_security', {}).get('cleartext_traffic', False)
        
        # Create simple HTML without complex f-strings
        html_content = '<div class="section"><h2>Security Analysis</h2>'
        
        # Code Protection
        html_content += '<h3>Code Protection</h3><ul>'
        if obfuscation_detected:
            html_content += '<li>Obfuscation: <i class="fas fa-check" style="color: #27ae60;"></i> Detected</li>'
        else:
            html_content += '<li>Obfuscation: <i class="fas fa-times" style="color: #e74c3c;"></i> Not Detected</li>'
        
        if debug_enabled:
            html_content += '<li>Debug Mode: <i class="fas fa-times" style="color: #e74c3c;"></i> Enabled</li>'
        else:
            html_content += '<li>Debug Mode: <i class="fas fa-check" style="color: #27ae60;"></i> Disabled</li>'
        html_content += '</ul>'
        
        # Network Security
        html_content += '<h3>Network Security</h3><ul>'
        if cleartext_allowed:
            html_content += '<li>Cleartext Traffic: <i class="fas fa-times" style="color: #e74c3c;"></i> Allowed</li>'
        else:
            html_content += '<li>Cleartext Traffic: <i class="fas fa-check" style="color: #27ae60;"></i> Blocked</li>'
        
        network_config = security.get('network_security', {}).get('network_security_config', 'Not specified')
        html_content += f'<li>Network Security Config: {network_config}</li>'
        html_content += '</ul>'
        
        # Component Security
        html_content += '<h3>Component Security</h3>'
        exported_components = security.get('component_security', {}).get('exported_components', 0)
        high_risk_exports = len(security.get('component_security', {}).get('high_risk_exports', []))
        html_content += f'<p>Exported Components: {exported_components}</p>'
        html_content += f'<p>High-Risk Exports: {high_risk_exports}</p>'
        
        html_content += '</div>'
        return html_content
    
    def _generate_secrets_section(self):
        """Generate comprehensive secrets analysis section with modern design"""
        secrets = self.results.get('secrets', {})
        
        hardcoded_secrets = secrets.get('hardcoded_secrets', [])
        total_secrets = len(hardcoded_secrets)
        
        # Count by risk level
        high_risk_secrets = len([s for s in hardcoded_secrets if s.get('risk_level') == 'high'])
        medium_risk_secrets = len([s for s in hardcoded_secrets if s.get('risk_level') == 'medium'])
        low_risk_secrets = len([s for s in hardcoded_secrets if s.get('risk_level') == 'low'])
        
        secrets_html = f"""
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon {'danger' if total_secrets > 0 else 'success'}">
                        <i class="fas fa-user-secret"></i>
                    </div>
                    <div>
                        <div class="card-title">Total Secrets</div>
                        <div class="card-value">{total_secrets}</div>
                        <div class="card-description">Hardcoded secrets found</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon danger">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div>
                        <div class="card-title">High Risk</div>
                        <div class="card-value">{high_risk_secrets}</div>
                        <div class="card-description">Critical secrets found</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div>
                        <div class="card-title">Medium Risk</div>
                        <div class="card-value">{medium_risk_secrets}</div>
                        <div class="card-description">Moderate risk secrets</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div>
                        <div class="card-title">Low Risk</div>
                        <div class="card-value">{low_risk_secrets}</div>
                        <div class="card-description">Low risk secrets</div>
                    </div>
                </div>
            </div>
        </div>
        """
        
        if hardcoded_secrets:
            # Group by type
            secret_types = {}
            for secret in hardcoded_secrets:
                secret_type = secret.get('type', 'Unknown')
                if secret_type not in secret_types:
                    secret_types[secret_type] = []
                secret_types[secret_type].append(secret)
            
            # Display by type
            for secret_type, type_secrets in secret_types.items():
                secrets_html += f"""
                <div class="card">
                    <div class="card-header">
                        <div class="card-icon warning">
                            <i class="fas fa-search"></i>
                        </div>
                        <div class="card-title">{html.escape(secret_type)} ({len(type_secrets)} found)</div>
                    </div>
                """
                
                for secret in type_secrets:
                    risk_level = secret.get('risk_level', 'unknown')
                    risk_class = 'high' if risk_level == 'high' else 'medium' if risk_level == 'medium' else 'low'
                    
                    secrets_html += f"""
                    <div class="vulnerability-card {risk_class} secret-item">
                        <div class="vuln-header">
                            <div class="vuln-title">{html.escape(secret.get('type', 'Unknown'))}</div>
                            <div class="vuln-risk {risk_class}">{risk_level.upper()}</div>
                        </div>
                        
                        <div class="vuln-description">
                            <strong>Value:</strong> <code>{html.escape(secret.get('value', 'Unknown'))}</code>
                        </div>
                        
                        <div class="vuln-details">
                            <h4><i class="fas fa-info-circle"></i> Details</h4>
                            <p><strong>File:</strong> {html.escape(secret.get('file', 'Unknown'))}</p>
                            <p><strong>Line:</strong> {secret.get('line_number', 'Unknown')}</p>
                            <p><strong>Context:</strong> <code>{html.escape(secret.get('context', 'No context available')[:200])}...</code></p>
                        </div>
                    </div>
                    """
                
                secrets_html += "</div>"
        else:
            secrets_html += """
            <div class="card">
                <div class="card-header">
                    <div class="card-icon success">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="card-title">No Hardcoded Secrets Detected!</div>
                </div>
                <p>Great! No hardcoded secrets were found in this APK analysis.</p>
            </div>
            """
        
        # Firebase configurations
        firebase_configs = secrets.get('firebase_configs', [])
        if firebase_configs:
            secrets_html += f"""
            <h3>🔥 Firebase Configurations ({len(firebase_configs)} found)</h3>
            <div class="vulnerability medium">
                <p><strong>Firebase configuration files detected:</strong></p>
                <ul>
            """
            for config in firebase_configs:
                secrets_html += f"<li>{html.escape(config.get('file', 'Unknown'))}</li>"
            secrets_html += "</ul></div>"
        
        # Base64 data
        base64_data = secrets.get('base64_data', [])
        if base64_data:
            secrets_html += f"""
            <h3>📄 Base64 Data ({len(base64_data)} found)</h3>
            """
            for data in base64_data[:10]:  # Limit to first 10
                secrets_html += f"""
                <div class="vulnerability low">
                    <strong>File:</strong> {html.escape(data.get('file', 'Unknown'))}<br>
                    <strong>Size:</strong> {data.get('size', 'Unknown')} bytes<br>
                    <strong>Type:</strong> {html.escape(data.get('type', 'Unknown'))}
                </div>
                """
        
        secrets_html += "</div>"
        return secrets_html
    
    def _generate_native_section(self):
        """Generate native libraries section"""
        native = self.results.get('native', {})
        
        if not native.get('has_native_libs'):
                    return """
        <div class="section">
            <h2>Native Libraries</h2>
            <p>No native libraries found</p>
        </div>
        """
        
        native_html = """
        <div class="section">
            <h2>Native Libraries Analysis</h2>
        """
        
        architectures = native.get('architectures', [])
        total_libs = sum(arch.get('library_count', 0) for arch in architectures)
        
        native_html += f"<p><strong>Total Libraries:</strong> {total_libs}</p>"
        native_html += f"<p><strong>Architectures:</strong> {', '.join(arch.get('name', 'Unknown') for arch in architectures)}</p>"
        
        # Security features analysis
        if architectures:
            native_html += "<h3>Security Features</h3><table><tr><th>Library</th><th>NX</th><th>Stack Canary</th><th>RELRO</th><th>PIE</th></tr>"
            
            for arch in architectures:
                for lib in arch.get('libraries', [])[:5]:  # Limit display
                    security = lib.get('security_features', {})
                    native_html += f"""
                    <tr>
                        <td>{html.escape(lib.get('name', 'Unknown'))}</td>
                        <td>{'✅' if security.get('nx') else '❌'}</td>
                        <td>{'✅' if security.get('stack_canary') else '❌'}</td>
                        <td>{'✅' if security.get('relro') else '❌'}</td>
                        <td>{'✅' if security.get('pie') else '❌'}</td>
                    </tr>
                    """
            
            native_html += "</table>"
        
        native_html += "</div>"
        return native_html
    
    def _generate_assets_section(self):
        """Generate comprehensive assets analysis section"""
        assets = self.results.get('assets', {})
        
        assets_html = """
        <div class="section">
            <h2>📁 Assets & Resources Analysis</h2>
        """
        
        # Basic statistics
        total_files = len(assets.get('files', []))
        total_size = sum(file.get('size', 0) for file in assets.get('files', []))
        
        assets_html += f"""
        <div class="summary">
            <h3>📊 Assets Statistics</h3>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div class="metric">
                    <div>Total Files</div>
                    <div class="risk-low">{total_files}</div>
                </div>
                <div class="metric">
                    <div>Total Size</div>
                    <div class="risk-low">{total_size:,} bytes</div>
                </div>
            </div>
        </div>
        """
        
        # File type analysis
        files = assets.get('files', [])
        if files:
            # Group by file type
            file_types = {}
            for file in files:
                file_type = file.get('type', 'Unknown')
                if file_type not in file_types:
                    file_types[file_type] = []
                file_types[file_type].append(file)
            
            assets_html += "<h3>📄 File Type Analysis</h3>"
            for file_type, type_files in file_types.items():
                assets_html += f"""
                <h4>🔍 {html.escape(file_type)} ({len(type_files)} files)</h4>
                """
                
                # Show first 10 files of each type
                for file in type_files[:10]:
                    assets_html += f"""
                    <div class="vulnerability low">
                        <strong>Path:</strong> {html.escape(file.get('path', 'Unknown'))}<br>
                        <strong>Size:</strong> {file.get('size', 0):,} bytes<br>
                        <strong>Type:</strong> {html.escape(file.get('type', 'Unknown'))}
                    </div>
                    """
                
                if len(type_files) > 10:
                    assets_html += f"<p><em>... and {len(type_files) - 10} more files</em></p>"
        
        # Interesting files
        interesting_files = []
        for file in files:
            file_path = file.get('path', '').lower()
            if any(pattern in file_path for pattern in [
                'config', 'json', 'xml', 'properties', 'txt', 'log', 'db', 'sqlite',
                'key', 'cert', 'pem', 'p12', 'keystore', 'jks'
            ]):
                interesting_files.append(file)
        
        if interesting_files:
            assets_html += "<h3>🔍 Interesting Files</h3>"
            for file in interesting_files[:20]:  # Limit display
                risk_level = 'medium' if any(risk in file.get('path', '').lower() for risk in ['key', 'cert', 'pem', 'p12', 'keystore', 'jks']) else 'low'
                assets_html += f"""
                <div class="vulnerability {risk_level}">
                    <strong>Path:</strong> {html.escape(file.get('path', 'Unknown'))}<br>
                    <strong>Size:</strong> {file.get('size', 0):,} bytes<br>
                    <strong>Type:</strong> {html.escape(file.get('type', 'Unknown'))}
                </div>
                """
        
        # URL analysis
        urls = assets.get('urls_found', [])
        if urls:
            assets_html += f"<h3>🌐 URLs Found ({len(urls)} URLs)</h3>"
            for url in urls[:20]:  # Limit display
                risk_level = 'high' if url.startswith('http://') else 'medium'
                assets_html += f"""
                <div class="vulnerability {risk_level}">
                    <code>{html.escape(url)}</code>
                </div>
                """
        
        # Error analysis
        errors = assets.get('errors', [])
        if errors:
            assets_html += f"<h3>❌ Analysis Errors ({len(errors)} errors)</h3>"
            for error in errors[:10]:  # Limit display
                assets_html += f"""
                <div class="vulnerability high">
                    <code>{html.escape(str(error))}</code>
                </div>
                """
        
        assets_html += "</div>"
        return assets_html
    
    def _generate_vulnerabilities_section(self):
        """Generate comprehensive vulnerabilities section with detailed information"""
        security = self.results.get('security', {})
        vulnerabilities = security.get('vulnerability_summary', [])
        
        vuln_html = """
        <div class="section">
            <h2>🔍 Comprehensive Vulnerabilities Analysis</h2>
        """
        
        if vulnerabilities:
            # Group vulnerabilities by risk level
            critical = [v for v in vulnerabilities if v.get('risk', '').lower() == 'critical']
            high = [v for v in vulnerabilities if v.get('risk', '').lower() == 'high']
            medium = [v for v in vulnerabilities if v.get('risk', '').lower() == 'medium']
            low = [v for v in vulnerabilities if v.get('risk', '').lower() == 'low']
            
            vuln_html += f"""
            <div class="summary">
                <h3>📊 Vulnerability Statistics</h3>
                <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                    <div class="metric">
                        <div>Critical</div>
                        <div class="risk-high">{len(critical)}</div>
                    </div>
                    <div class="metric">
                        <div>High</div>
                        <div class="risk-high">{len(high)}</div>
                    </div>
                    <div class="metric">
                        <div>Medium</div>
                        <div class="risk-medium">{len(medium)}</div>
                    </div>
                    <div class="metric">
                        <div>Low</div>
                        <div class="risk-low">{len(low)}</div>
                    </div>
                </div>
            </div>
            """
            
            # Group vulnerabilities by category
            categories = {
                "Code and Data Security": [],
                "Network and Communication": [],
                "Authentication and Authorization": [],
                "Platform/API/Intent": [],
                "Other and Special": []
            }
            
            for vuln in vulnerabilities:
                category = vuln.get('category', 'Other and Special')
                if category in categories:
                    categories[category].append(vuln)
                else:
                    categories["Other and Special"].append(vuln)
            
            # Display vulnerabilities by category
            for category, vulns in categories.items():
                if vulns:
                    # Count by risk level
                    critical_count = len([v for v in vulns if v.get('risk', '').lower() == 'critical'])
                    high_count = len([v for v in vulns if v.get('risk', '').lower() == 'high'])
                    medium_count = len([v for v in vulns if v.get('risk', '').lower() == 'medium'])
                    low_count = len([v for v in vulns if v.get('risk', '').lower() == 'low'])
                    
                    vuln_html += f"""
                    <h3>🔍 {category} Vulnerabilities ({len(vulns)})</h3>
                    <div style="display: flex; justify-content: space-around; margin: 10px 0; background: #f8f9fa; padding: 10px; border-radius: 5px;">
                        <div><strong>Critical:</strong> <span class="risk-high">{critical_count}</span></div>
                        <div><strong>High:</strong> <span class="risk-high">{high_count}</span></div>
                        <div><strong>Medium:</strong> <span class="risk-medium">{medium_count}</span></div>
                        <div><strong>Low:</strong> <span class="risk-low">{low_count}</span></div>
                    </div>
                    """
                    
                    for vuln in vulns:
                        risk = vuln.get('risk', '').lower()
                        details = vuln.get('details', [])
                        detection_method = vuln.get('detection_method', 'N/A')
                        remediation = vuln.get('remediation', 'N/A')
                        
                        vuln_html += f"""
                        <div class="vulnerability {risk}">
                            <h4>🔴 {vuln.get('type', 'Unknown Vulnerability')}</h4>
                            <table style="width: 100%; margin: 10px 0;">
                                <tr><td><strong>Risk Level:</strong></td><td><span class="risk-{risk}">{vuln.get('risk', 'Unknown')}</span></td></tr>
                                <tr><td><strong>Description:</strong></td><td>{html.escape(vuln.get('description', 'No description'))}</td></tr>
                                <tr><td><strong>Impact:</strong></td><td>{html.escape(vuln.get('impact', 'Unknown'))}</td></tr>
                                <tr><td><strong>Detection Method:</strong></td><td>{html.escape(detection_method)}</td></tr>
                                <tr><td><strong>Remediation:</strong></td><td>{html.escape(remediation)}</td></tr>
                                <tr><td><strong>File:</strong></td><td>{html.escape(vuln.get('file', 'N/A'))}</td></tr>
                                <tr><td><strong>Line:</strong></td><td>{html.escape(str(vuln.get('line', 'N/A')))}</td></tr>
                                <tr><td><strong>Class:</strong></td><td>{html.escape(vuln.get('class', 'N/A'))}</td></tr>
                                <tr><td><strong>Method:</strong></td><td>{html.escape(vuln.get('method', 'N/A'))}</td></tr>
                            </table>
                        """
                        
                        if details:
                            vuln_html += "<strong>Details:</strong><ul>"
                            for detail in details:
                                vuln_html += f"<li>{html.escape(str(detail))}</li>"
                            vuln_html += "</ul>"
                        
                        vuln_html += "</div>"
        else:
            vuln_html += """
            <div class="summary" style="background: #d4edda; border-color: #c3e6cb;">
                <h3>✅ No Vulnerabilities Detected!</h3>
                <p>Congratulations! No security vulnerabilities were found in this APK analysis.</p>
            </div>
            """
        
        vuln_html += "</div>"
        return vuln_html
    
    def _generate_recommendations_section(self):
        """Generate recommendations section"""
        security = self.results.get('security', {})
        recommendations = security.get('recommendations', [])
        
        if not recommendations:
                    return """
        <div class="section">
            <h2>Recommendations</h2>
            <p>No specific recommendations generated</p>
        </div>
        """
        
        rec_html = """
        <div class="section">
            <h2>Security Recommendations</h2>
        """
        
        # Group by priority
        high_priority = [r for r in recommendations if r.get('priority', '').lower() == 'high']
        medium_priority = [r for r in recommendations if r.get('priority', '').lower() == 'medium']
        low_priority = [r for r in recommendations if r.get('priority', '').lower() == 'low']
        
        for priority, recs in [('High Priority', high_priority), ('Medium Priority', medium_priority), ('Low Priority', low_priority)]:
            if recs:
                rec_html += f"<h3>{priority}</h3>"
                for rec in recs:
                    rec_html += f"""
                    <div class="vulnerability {priority.split()[0].lower()}">
                        <strong>{html.escape(rec.get('recommendation', 'Unknown'))}</strong><br>
                        Category: {html.escape(rec.get('category', 'General'))}<br>
                        Details: {html.escape(rec.get('details', 'No details'))}
                    </div>
                    """
        
        rec_html += "</div>"
        return rec_html
    
    def _generate_text_summary(self):
        """Generate text summary report"""
        summary_file = self.output_dir / "security_summary.txt"
        
        security = self.results.get('security', {})
        manifest = self.results.get('manifest', {})
        
        summary = f"""
APK SECURITY ANALYSIS SUMMARY
============================

File: {self.results.get('apk_path', 'Unknown')}
Analysis Date: {self.results.get('analysis_time', 'Unknown')}
Package: {manifest.get('package_name', 'Unknown')}

SECURITY SCORE: {security.get('security_score', 0)}/100

CRITICAL FINDINGS:
"""
        
        # Add vulnerabilities
        vulnerabilities = security.get('vulnerability_summary', [])
        critical_vulns = [v for v in vulnerabilities if v.get('risk', '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('risk', '').lower() == 'high']
        
        if critical_vulns or high_vulns:
            for vuln in critical_vulns + high_vulns:
                summary += f"- {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}\n"
        else:
            summary += "- No critical or high-risk vulnerabilities found\n"
        
        # Add secrets summary
        secrets = self.results.get('secrets', {})
        secrets_found = secrets.get('secrets_found', [])
        high_risk_secrets = [s for s in secrets_found if s.get('risk_level') == 'high']
        
        summary += f"\nSECRETS ANALYSIS:\n"
        summary += f"- Total secrets found: {len(secrets_found)}\n"
        summary += f"- High-risk secrets: {len(high_risk_secrets)}\n"
        
        # Add permissions summary
        dangerous_perms = manifest.get('dangerous_permissions', [])
        summary += f"\nPERMISSIONS:\n"
        summary += f"- Dangerous permissions: {len(dangerous_perms)}\n"
        
        # Add recommendations
        recommendations = security.get('recommendations', [])
        high_priority_recs = [r for r in recommendations if r.get('priority', '').lower() == 'high']
        
        if high_priority_recs:
            summary += f"\nTOP RECOMMENDATIONS:\n"
            for rec in high_priority_recs[:5]:
                summary += f"- {rec.get('recommendation', 'Unknown')}\n"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(summary)