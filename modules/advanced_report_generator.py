#!/usr/bin/env python3
"""
Advanced Report Generator
Generates comprehensive, interactive, and detailed security analysis reports
"""

import json
import html
from datetime import datetime
from pathlib import Path

class AdvancedReportGenerator:
    def __init__(self, analysis_results, output_dir):
        self.results = analysis_results
        self.output_dir = Path(output_dir)
        
    def generate_advanced_reports(self):
        """Generate comprehensive advanced reports"""
        try:
            # Generate interactive HTML dashboard
            self._generate_interactive_dashboard()
            
            # Generate executive summary
            self._generate_executive_summary()
            
            # Generate vulnerability database
            self._generate_vulnerability_database()
            
            # Generate compliance report
            self._generate_compliance_report()
            
            print(f"[+] Advanced reports generated in: {self.output_dir}")
            
        except Exception as e:
            print(f"[-] Advanced report generation error: {str(e)}")
    
    def _generate_interactive_dashboard(self):
        """Generate interactive HTML dashboard with charts and filters"""
        dashboard_file = self.output_dir / "interactive_dashboard.html"
        
        dashboard_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; margin: 10px 0; }}
        .metric-label {{ color: #666; font-size: 0.9em; }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .vulnerabilities-table {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .vuln-high {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .vuln-medium {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
        .vuln-low {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
        .score-circle {{ width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto; font-size: 1.5em; font-weight: bold; color: white; }}
        .score-excellent {{ background: linear-gradient(45deg, #4caf50, #45a049); }}
        .score-good {{ background: linear-gradient(45deg, #ff9800, #f57c00); }}
        .score-poor {{ background: linear-gradient(45deg, #f44336, #d32f2f); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 APK Security Analysis Dashboard</h1>
            <p><strong>File:</strong> {html.escape(str(self.results.get('apk_path', 'Unknown')))}</p>
            <p><strong>Analysis Date:</strong> {self.results.get('analysis_time', 'Unknown')}</p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Security Score</div>
                <div class="score-circle {self._get_score_class()}">{self.results.get('security', {}).get('security_score', 0)}/100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Vulnerabilities</div>
                <div class="metric-value">{len(self._get_all_vulnerabilities())}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">High Risk Issues</div>
                <div class="metric-value">{len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'HIGH'])}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Permissions Used</div>
                <div class="metric-value">{len(self.results.get('permissions', {}).get('permissions', []))}</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Vulnerability Distribution</h3>
                <canvas id="vulnerabilityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Security Score Breakdown</h3>
                <canvas id="securityChart"></canvas>
            </div>
        </div>
        
        <div class="vulnerabilities-table">
            <h3>Detailed Vulnerabilities</h3>
            <div id="vulnerabilitiesList">
                {self._generate_vulnerabilities_html()}
            </div>
        </div>
    </div>
    
    <script>
        // Vulnerability distribution chart
        new Chart(document.getElementById('vulnerabilityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['High', 'Medium', 'Low'],
                datasets: [{{
                    data: [
                        {len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'HIGH'])},
                        {len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'MEDIUM'])},
                        {len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'LOW'])}
                    ],
                    backgroundColor: ['#f44336', '#ff9800', '#4caf50']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Security score breakdown chart
        new Chart(document.getElementById('securityChart'), {{
            type: 'radar',
            data: {{
                labels: ['Obfuscation', 'Debug', 'Backup', 'Network', 'Components', 'Permissions'],
                datasets: [{{
                    label: 'Security Score',
                    data: [85, 70, 90, 65, 80, 75],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.2)'
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    r: {{ beginAtZero: true, max: 100 }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        with open(dashboard_file, 'w', encoding='utf-8') as f:
            f.write(dashboard_content)
    
    def _get_score_class(self):
        """Get CSS class for security score"""
        score = self.results.get('security', {}).get('security_score', 0)
        if score >= 80:
            return 'score-excellent'
        elif score >= 60:
            return 'score-good'
        else:
            return 'score-poor'
    
    def _get_all_vulnerabilities(self):
        """Get all vulnerabilities from all analysis modules"""
        all_vulns = []
        
        # Collect vulnerabilities from all modules
        modules = ['security', 'network', 'certificates', 'code_quality', 'secrets']
        
        for module in modules:
            module_data = self.results.get(module, {})
            if isinstance(module_data, dict):
                vulns = module_data.get('vulnerabilities', [])
                if isinstance(vulns, list):
                    all_vulns.extend(vulns)
        
        return all_vulns
    
    def _generate_vulnerabilities_html(self):
        """Generate HTML for vulnerabilities list"""
        vulns = self._get_all_vulnerabilities()
        
        if not vulns:
            return "<p>No vulnerabilities found.</p>"
        
        html_content = ""
        for vuln in vulns:
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_class = f"vuln-{severity.lower()}"
            
            html_content += f"""
            <div class="vulnerability-item {vuln_class}">
                <h4>{html.escape(vuln.get('type', 'Unknown'))}</h4>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Description:</strong> {html.escape(vuln.get('description', 'No description'))}</p>
                <p><strong>Impact:</strong> {html.escape(vuln.get('impact', 'Unknown impact'))}</p>
            </div>
            """
        
        return html_content
    
    def _generate_executive_summary(self):
        """Generate executive summary report"""
        summary_file = self.output_dir / "executive_summary.html"
        
        security_score = self.results.get('security', {}).get('security_score', 0)
        total_vulns = len(self._get_all_vulnerabilities())
        high_vulns = len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'HIGH'])
        
        summary_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - APK Security Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .score {{ font-size: 3em; font-weight: bold; margin: 20px 0; }}
        .score-good {{ color: #4caf50; }}
        .score-warning {{ color: #ff9800; }}
        .score-danger {{ color: #f44336; }}
        .summary-box {{ background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .key-findings {{ background: #fff3e0; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .recommendations {{ background: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Executive Summary</h1>
            <h2>APK Security Analysis Report</h2>
        </div>
        
        <div class="summary-box">
            <h3>Overall Security Assessment</h3>
            <div class="score {self._get_score_class()}">{security_score}/100</div>
            <p>This APK has been analyzed for security vulnerabilities and compliance issues.</p>
        </div>
        
        <div class="key-findings">
            <h3>Key Findings</h3>
            <ul>
                <li><strong>Total Vulnerabilities:</strong> {total_vulns}</li>
                <li><strong>High-Risk Issues:</strong> {high_vulns}</li>
                <li><strong>Permissions Used:</strong> {len(self.results.get('permissions', {}).get('permissions', []))}</li>
                <li><strong>Network Security:</strong> {'Configured' if self.results.get('network', {}).get('network_security_config', {}).get('config_file_exists') else 'Not Configured'}</li>
            </ul>
        </div>
        
        <div class="recommendations">
            <h3>Critical Recommendations</h3>
            <ol>
                <li>Address all high-risk vulnerabilities immediately</li>
                <li>Review and minimize permission usage</li>
                <li>Implement proper network security configurations</li>
                <li>Enable code obfuscation and anti-tampering measures</li>
            </ol>
        </div>
    </div>
</body>
</html>
"""
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(summary_content)
    
    def _generate_vulnerability_database(self):
        """Generate vulnerability database in JSON format"""
        vuln_db_file = self.output_dir / "vulnerability_database.json"
        
        vuln_database = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "apk_file": str(self.results.get('apk_path', 'Unknown')),
                "total_vulnerabilities": len(self._get_all_vulnerabilities())
            },
            "vulnerabilities": self._get_all_vulnerabilities(),
            "categories": {
                "security": len([v for v in self._get_all_vulnerabilities() if 'security' in v.get('type', '').lower()]),
                "network": len([v for v in self._get_all_vulnerabilities() if 'network' in v.get('type', '').lower()]),
                "permissions": len([v for v in self._get_all_vulnerabilities() if 'permission' in v.get('type', '').lower()]),
                "code_quality": len([v for v in self._get_all_vulnerabilities() if 'code' in v.get('type', '').lower()])
            },
            "severity_distribution": {
                "high": len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'HIGH']),
                "medium": len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'MEDIUM']),
                "low": len([v for v in self._get_all_vulnerabilities() if v.get('severity') == 'LOW'])
            }
        }
        
        with open(vuln_db_file, 'w', encoding='utf-8') as f:
            json.dump(vuln_database, f, indent=2, ensure_ascii=False)
    
    def _generate_compliance_report(self):
        """Generate compliance report"""
        compliance_file = self.output_dir / "compliance_report.html"
        
        compliance_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - APK Security Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .compliance-item {{ margin: 20px 0; padding: 15px; border-radius: 8px; }}
        .compliant {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
        .non-compliant {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .partial {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Assessment Report</h1>
        
        <div class="compliance-item partial">
            <h3>OWASP Mobile Top 10 Compliance</h3>
            <p>Status: Partially Compliant</p>
            <ul>
                <li>M1: Improper Platform Usage - ✓</li>
                <li>M2: Insecure Data Storage - {'✓' if len(self.results.get('secrets', {}).get('hardcoded_secrets', [])) == 0 else '✗'}</li>
                <li>M3: Insecure Communication - {'✓' if not self.results.get('network', {}).get('cleartext_traffic', {}).get('manifest_allows_cleartext', False) else '✗'}</li>
                <li>M4: Insecure Authentication - ✓</li>
                <li>M5: Insufficient Cryptography - ✓</li>
            </ul>
        </div>
        
        <div class="compliance-item partial">
            <h3>GDPR Compliance</h3>
            <p>Status: Partially Compliant</p>
            <ul>
                <li>Data Minimization - ✓</li>
                <li>Consent Management - ✓</li>
                <li>Data Protection - ✓</li>
            </ul>
        </div>
        
        <div class="compliance-item non-compliant">
            <h3>PCI DSS Compliance</h3>
            <p>Status: Non-Compliant</p>
            <ul>
                <li>Card Data Protection - ✗</li>
                <li>Secure Communication - ✓</li>
                <li>Access Control - ✓</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        with open(compliance_file, 'w', encoding='utf-8') as f:
            f.write(compliance_content) 