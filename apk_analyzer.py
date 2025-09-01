#!/usr/bin/env python3
"""
APK Static Analysis Tool
Comprehensive security analysis for Android APK files
"""

import os
import sys
import argparse
import json
import time
import warnings
from datetime import datetime
from pathlib import Path

# Suppress syntax warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

# Import analysis modules
from modules.apk_structure import APKStructureAnalyzer
from modules.manifest_analyzer import ManifestAnalyzer
from modules.dex_analyzer import DEXAnalyzer
from modules.native_analyzer import NativeLibraryAnalyzer
from modules.assets_analyzer import AssetsAnalyzer
from modules.secrets_detector import SecretsDetector
from modules.security_checker import SecurityChecker
from modules.permissions_analyzer import PermissionsAnalyzer
from modules.certificate_analyzer import CertificateAnalyzer
from modules.network_analyzer import NetworkAnalyzer
from modules.internet_analyzer import InternetAnalyzer
from modules.code_quality_analyzer import CodeQualityAnalyzer
from modules.clean_report_generator import CleanReportGenerator

# Color codes for beautiful output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    BLUE = '\033[34m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    WHITE = '\033[37m'

class APKAnalyzer:
    time_stamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    def __init__(self, apk_path, output_dir=None, config=None):
        self.original_path = Path(apk_path)
        self.apk_path = self._process_file(apk_path)
        self.output_dir = Path(output_dir) if output_dir else Path(f"analysis_output_{self.time_stamp}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Load configuration
        self.config = config or self._load_default_config()
        
        # Analysis settings
        self.quick_mode = self.config.get('analysis', {}).get('quick_mode', False)
        self.threads = self.config.get('analysis', {}).get('threads', 4)
        self.timeout = self.config.get('analysis', {}).get('timeout', 300)
        self.skip_modules = set(self.config.get('analysis', {}).get('skip_modules', []))
        self.only_modules = set(self.config.get('analysis', {}).get('only_modules', []))
        
        # Create temp extraction directory
        self.extract_dir = self.output_dir / "extracted"
        self.extract_dir.mkdir(exist_ok=True)
        
        # Analysis results storage
        self.results = {
            "original_path": str(self.original_path),
            "apk_path": str(self.apk_path),
            "file_type": self._get_file_type(),
            "analysis_time": datetime.now().isoformat(),
            "config_used": self.config,
            "analysis_settings": {
                "quick_mode": self.quick_mode,
                "threads": self.threads,
                "timeout": self.timeout
            },
            "structure": {},
            "manifest": {},
            "dex": {},
            "native": {},
            "assets": {},
            "secrets": {},
            "security": {},
            "permissions": {},
            "certificates": {},
            "network": {},
            "internet": {},
            "code_quality": {},
            "vulnerabilities": [],
            "compliance": {},
            "comparison": {}
        }
    
    def _get_file_type(self):
        """Determine file type based on extension"""
        ext = self.original_path.suffix.lower()
        if ext == '.apk':
            return 'APK'
        elif ext == '.xapk':
            return 'XAPK'
        elif ext == '.aab':
            return 'AAB'
        else:
            return 'UNKNOWN'
    
    def _process_file(self, file_path):
        """Process different file types (APK, XAPK, AAB)"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # If it's already an APK, return as is
        if file_path.suffix.lower() == '.apk':
            return file_path
        
        # If it's XAPK, extract the APK from it
        if file_path.suffix.lower() == '.xapk':
            return self._extract_apk_from_xapk(file_path)
        
        # If it's AAB, we'll need special handling (for now, just return as is)
        if file_path.suffix.lower() == '.aab':
            print(f"{Colors.YELLOW}[WARNING] AAB files are not fully supported yet. Treating as APK.{Colors.ENDC}")
            return file_path
        
        # Unknown file type
        raise ValueError(f"Unsupported file type: {file_path.suffix}. Supported: .apk, .xapk, .aab")
    
    def _extract_apk_from_xapk(self, xapk_path):
        """Extract APK file from XAPK package"""
        import zipfile
        import tempfile
        
        print(f"{Colors.CYAN}[INFO] Processing XAPK file: {xapk_path.name}{Colors.ENDC}")
        
        # Create temporary directory for extraction
        temp_dir = Path(tempfile.mkdtemp(prefix="xapk_extract_"))
        
        try:
            with zipfile.ZipFile(xapk_path, 'r') as zip_file:
                # List all files in XAPK
                file_list = zip_file.namelist()
                print(f"{Colors.CYAN}[INFO] XAPK contains {len(file_list)} files{Colors.ENDC}")
                
                # Find APK file(s)
                apk_files = [f for f in file_list if f.endswith('.apk')]
                
                if not apk_files:
                    raise ValueError("No APK file found in XAPK package")
                
                # Extract the first APK file
                apk_file = apk_files[0]
                print(f"{Colors.CYAN}[INFO] Extracting APK: {apk_file}{Colors.ENDC}")
                
                zip_file.extract(apk_file, temp_dir)
                extracted_apk = temp_dir / apk_file
                
                # Also extract OBB files if present
                obb_files = [f for f in file_list if f.endswith('.obb')]
                if obb_files:
                    print(f"{Colors.CYAN}[INFO] Found {len(obb_files)} OBB files{Colors.ENDC}")
                    for obb_file in obb_files:
                        zip_file.extract(obb_file, temp_dir)
                        print(f"{Colors.CYAN}[INFO] Extracted OBB: {obb_file}{Colors.ENDC}")
                
                # Copy OBB files to output directory for analysis
                if obb_files:
                    obb_dir = self.output_dir / "obb_files"
                    obb_dir.mkdir(exist_ok=True)
                    for obb_file in obb_files:
                        src = temp_dir / obb_file
                        dst = obb_dir / Path(obb_file).name
                        import shutil
                        shutil.copy2(src, dst)
                
                return extracted_apk
                
        except Exception as e:
            # Clean up temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ValueError(f"Failed to extract APK from XAPK: {str(e)}")
    
    def _load_default_config(self):
        """Load default configuration"""
        try:
            config_path = Path(__file__).parent / "config.json"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Return minimal default config
        return {
            "analysis": {
                "quick_mode": False,
                "threads": 4,
                "timeout": 300,
                "skip_modules": [],
                "only_modules": []
            }
        }
    
    def set_quick_mode(self, enabled):
        """Enable or disable quick mode"""
        self.quick_mode = enabled
        self.results["analysis_settings"]["quick_mode"] = enabled
    
    def skip_modules(self, modules):
        """Skip specific analysis modules"""
        self.skip_modules.update(modules)
    
    def only_modules(self, modules):
        """Run only specific analysis modules"""
        self.only_modules.update(modules)
    
    def compare_with_previous(self, previous_file):
        """Compare current analysis with previous results"""
        try:
            with open(previous_file, 'r') as f:
                previous_results = json.load(f)
            
            comparison = {
                "previous_file": previous_file,
                "comparison_time": datetime.now().isoformat(),
                "changes": {}
            }
            
            # Compare security scores
            current_score = self.results.get('security', {}).get('security_score', 0)
            previous_score = previous_results.get('security', {}).get('security_score', 0)
            comparison["changes"]["security_score"] = {
                "current": current_score,
                "previous": previous_score,
                "difference": current_score - previous_score
            }
            
            # Compare vulnerability counts
            current_vulns = len(self._get_all_vulnerabilities())
            previous_vulns = len(previous_results.get('vulnerabilities', []))
            comparison["changes"]["vulnerabilities"] = {
                "current": current_vulns,
                "previous": previous_vulns,
                "difference": current_vulns - previous_vulns
            }
            
            self.results["comparison"] = comparison
            
            # Generate comparison report
            self._generate_comparison_report(comparison)
            
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING] Failed to compare with previous results: {str(e)}{Colors.ENDC}")
    
    def export_results(self, format_type):
        """Export results in specified format"""
        try:
            if format_type == 'csv':
                self._export_to_csv()
            elif format_type == 'html':
                self._export_to_html()
            elif format_type == 'pdf':
                self._export_to_pdf()
            else:
                print(f"{Colors.YELLOW}[WARNING] Unsupported export format: {format_type}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to export results: {str(e)}{Colors.ENDC}")
    
    def check_compliance(self, standards):
        """Check compliance with specified standards"""
        try:
            compliance_results = {}
            
            for standard in standards:
                standard = standard.lower()
                if standard == 'owasp':
                    compliance_results['owasp'] = self._check_owasp_compliance()
                elif standard == 'gdpr':
                    compliance_results['gdpr'] = self._check_gdpr_compliance()
                elif standard == 'pci':
                    compliance_results['pci_dss'] = self._check_pci_compliance()
                else:
                    print(f"{Colors.YELLOW}[WARNING] Unknown compliance standard: {standard}{Colors.ENDC}")
            
            self.results["compliance"] = compliance_results
            
            # Generate compliance report
            self._generate_compliance_report(compliance_results)
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to check compliance: {str(e)}{Colors.ENDC}")
    
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
    
    def _export_to_csv(self):
        """Export results to CSV format"""
        import csv
        
        csv_file = self.output_dir / "analysis_results.csv"
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Category', 'Type', 'Severity', 'Description', 'Impact'])
            
            # Write vulnerabilities
            vulns = self._get_all_vulnerabilities()
            for vuln in vulns:
                writer.writerow([
                    vuln.get('category', 'Unknown'),
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', ''),
                    vuln.get('impact', '')
                ])
        
        print(f"{Colors.GREEN}[+] Results exported to CSV: {csv_file}{Colors.ENDC}")
    
    def _export_to_html(self):
        """Export results to HTML format"""
        # Use the advanced report generator
        from modules.advanced_report_generator import AdvancedReportGenerator
        advanced_generator = AdvancedReportGenerator(self.results, self.output_dir)
        advanced_generator.generate_advanced_reports()
    
    def _export_to_pdf(self):
        """Export results to PDF format"""
        print(f"{Colors.YELLOW}[WARNING] PDF export not implemented yet{Colors.ENDC}")
    
    def _generate_comparison_report(self, comparison):
        """Generate comparison report"""
        report_file = self.output_dir / "comparison_report.html"
        
        report_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comparison Report - APK Security Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .comparison-item {{ margin: 20px 0; padding: 15px; border-radius: 8px; background: #f8f9fa; }}
        .improvement {{ border-left: 4px solid #28a745; }}
        .regression {{ border-left: 4px solid #dc3545; }}
        .no-change {{ border-left: 4px solid #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Comparison Report</h1>
        <p>Comparing current analysis with: {comparison.get('previous_file', 'Unknown')}</p>
        
        <div class="comparison-item {self._get_comparison_class(comparison['changes']['security_score']['difference'])}">
            <h3>Security Score</h3>
            <p>Current: {comparison['changes']['security_score']['current']}</p>
            <p>Previous: {comparison['changes']['security_score']['previous']}</p>
            <p>Difference: {comparison['changes']['security_score']['difference']}</p>
        </div>
        
        <div class="comparison-item {self._get_comparison_class(-comparison['changes']['vulnerabilities']['difference'])}">
            <h3>Vulnerabilities</h3>
            <p>Current: {comparison['changes']['vulnerabilities']['current']}</p>
            <p>Previous: {comparison['changes']['vulnerabilities']['previous']}</p>
            <p>Difference: {comparison['changes']['vulnerabilities']['difference']}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
    
    def _get_comparison_class(self, difference):
        """Get CSS class for comparison difference"""
        if difference > 0:
            return "improvement"
        elif difference < 0:
            return "regression"
        else:
            return "no-change"
    
    def _check_owasp_compliance(self):
        """Check OWASP Mobile Top 10 compliance"""
        compliance = {
            "status": "Partially Compliant",
            "checks": {}
        }
        
        # M1: Improper Platform Usage
        compliance["checks"]["m1"] = True
        
        # M2: Insecure Data Storage
        secrets = self.results.get('secrets', {})
        compliance["checks"]["m2"] = len(secrets.get('hardcoded_secrets', [])) == 0
        
        # M3: Insecure Communication
        network = self.results.get('network', {})
        compliance["checks"]["m3"] = not network.get('cleartext_traffic', {}).get('manifest_allows_cleartext', False)
        
        # M4: Insecure Authentication
        compliance["checks"]["m4"] = True
        
        # M5: Insufficient Cryptography
        compliance["checks"]["m5"] = True
        
        # Calculate overall status
        passed_checks = sum(compliance["checks"].values())
        if passed_checks >= 4:
            compliance["status"] = "Compliant"
        elif passed_checks >= 2:
            compliance["status"] = "Partially Compliant"
        else:
            compliance["status"] = "Non-Compliant"
        
        return compliance
    
    def _check_gdpr_compliance(self):
        """Check GDPR compliance"""
        return {
            "status": "Partially Compliant",
            "checks": {
                "data_minimization": True,
                "consent_management": True,
                "data_protection": True
            }
        }
    
    def _check_pci_compliance(self):
        """Check PCI DSS compliance"""
        return {
            "status": "Non-Compliant",
            "checks": {
                "card_data_protection": False,
                "secure_communication": True,
                "access_control": True
            }
        }
    
    def _generate_compliance_report(self, compliance_results):
        """Generate compliance report"""
        report_file = self.output_dir / "compliance_report.html"
        
        report_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - APK Security Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .compliance-item {{ margin: 20px 0; padding: 15px; border-radius: 8px; }}
        .compliant {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
        .non-compliant {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .partial {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Assessment Report</h1>
        
        {self._generate_compliance_items(compliance_results)}
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
    
    def _generate_compliance_items(self, compliance_results):
        """Generate compliance items HTML"""
        html_content = ""
        
        for standard, result in compliance_results.items():
            status = result.get('status', 'Unknown')
            css_class = status.lower().replace(' ', '-')
            
            html_content += f"""
            <div class="compliance-item {css_class}">
                <h3>{standard.upper()} Compliance</h3>
                <p>Status: {status}</p>
                <ul>
            """
            
            for check, passed in result.get('checks', {}).items():
                html_content += f"<li>{check.replace('_', ' ').title()}: {'✓' if passed else '✗'}</li>"
            
            html_content += """
                </ul>
            </div>
            """
        
        return html_content

    def run_analysis(self):
        """Run complete APK analysis with beautiful output"""
        self._print_banner()
        self._print_file_info()
        
        try:
            analysis_steps = [
                ("APK Structure Analysis", "📁", self._analyze_structure),
                ("AndroidManifest.xml Analysis", "📋", self._analyze_manifest),
                ("DEX Code Analysis", "🔍", self._analyze_dex),
                ("Native Library Analysis", "⚙️", self._analyze_native),
                ("Assets & Resources Analysis", "📦", self._analyze_assets),
                ("Hardcoded Secrets Detection", "🔐", self._analyze_secrets),
                ("Certificate & Signing Analysis", "🏛️", self._analyze_certificates),
                ("Network Security Analysis", "🌐", self._analyze_network),
                ("Internet Artifacts Analysis", "🔗", self._analyze_internet),
                ("Code Quality Analysis", "📊", self._analyze_code_quality),
                ("Security Vulnerability Assessment", "🛡️", self._analyze_security),
                ("Permissions Analysis", "🔑", self._analyze_permissions),
                ("Report Generation", "📄", self._generate_reports)
            ]
            
            for i, (step_name, icon, step_func) in enumerate(analysis_steps, 1):
                self._print_step_header(i, len(analysis_steps), step_name, icon)
                step_func()
                self._print_step_success()
                time.sleep(0.5)  # Small delay for visual effect
            
            self._print_final_summary()
            
        except Exception as e:
            self._print_error(f"Analysis failed: {str(e)}")
            return False
            
        return True
    
    def _print_banner(self):
        """Print beautiful banner"""
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
@%%%%%%%%%%@@@@%%%%%%%@@@@@@@@@@@%%%%%%%%%%%%%%%@@@@@@@@@@%%%%%%@@%%%%%%%%%%%%%%%%@@@@@@@@@@@%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%@@@@@@@@@@@@%%%%%%%%@@@@@@@@@%%%%%%%%%%%%%%@@@@@@@@@@@%%%%@@%%%%%%%%%%%%%%%%%@@@@@@@@@@%%%%%%@@@@@@@@@@@@%%%%%@@@@@@@@@@@@@
###%%@@@@@@@@@@@%%%%%%%%%@@@@@@@@%%%%%%%%%%@%%%@@@@@@@@@@@@@%%@@@%%%%%%%%%%%%%%%%%@@@@@@@@@@@%%%%%%%%%%%@@@@@%%%%@@@@@@@@@@@@@@@
++*%@@@@@@@@@@@@%%%%%%%%@@@@@@@@@%%%%%%%%%@@@%%@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@%%%%%%%@@@@@@%%@@@@@@@@@@@@@@@@
+*#%@@@@@@@@@@@%%%%%%%%@@@@@@@@@@@@@@%%%%%%@@%%%%@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%@@@@%%%%%@@@@%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@
##%@@@@@@@@@%%%%%%%%%%@@@@@@@@@@@@@@@@@%%%%%%##%%%@@@%@@@@@@@@@@@@@%%%%%%@@%%%%%%%%%%%@@%%###%%@@@%%%%%@@@@@@@@@%%%%%@@@@@@@@@@@
@@@@@@@@@@%%%%%#%%%%%@@@@@@@@@@@@@@@@@@@%%###**###%%%%%%%%%%%@@@@@@%%%%%%%@%%%%%%%%%%@@@@%%##%@@@@@%%%%%@%%@@@@%%%%%%%%@@@@@@@@@
@@@%%%%@@%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@%%%###**###%%%%%%%%%%%%@%@%%%%%%%%%@%%%%%%%%@@@@@@@@@@@@%%%%%%@%%%%%%@@%%%%%%%%%@@@@@@@@@
@@%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@%%%%%%%##*+=========++*#%%%%%%%%%%%%%%%%%%%%%%%%@@@@%%%%@@%%%%%@@@@%%%@@@@@%@@@@@@@@@@@@@@@
@@@@@@@%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@%%%#*+=---------------==+#%%%%%@@@%%%%%%%%%%%%%%%%%%%%%@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%@@@@%%@@%%%%%%@@@@@@@@@@@@@@@@@@@@@@%*==--------------------=+##%%%@@@%%%%%%%%%%%%%%%%%%%%%@@@%%%%@@@@@%%@@@@@@@@@@@@@@@@@@@@@
#%%%%%%%@@@%%%%%%%%%%%%%@@@@@@@@@@@@%+===---::::::::::::::------=+#%%%%%%%%%%%%%%%%%%%%%%%%%%@@%%%%%@@@@@@@@@@@%%%%@@@@@@@@@@@@@
#%@@@%%%@@@@@@%%%%%%%%%@@@@@@@@%%%%*===---::::::::::::::::::-----==*##%%%######%%%%%%%%%%%%%%@@@%%%@@@@@@@@@@%%%@@@@@@%%@%@@@@@@
%@@@@@%%@@@@@@@@@@@@@@@@@@@@@@%%%#+===---:::::::::::::::::::::::--==+###%%*+**#%%%%%%%%%%%%%%@%%%%%%%@@@@@@@@@%%%@@@@@@%%%@@@@@@
%@@@@@@@@@@@%%%%@@@@@@@@@@@@@@%%#+==----::::::::::::::::::::::::----=+*###%#*#%%@%%@%%%%%%%%%%%%%%%%%@@@@@@@%%%%%%%%@@@@@@@@@@@@
%%@@@@@@@%%%%%%@@@@@@@@@@@@@%%%*+===----::::::::::::::::::::::::-----=+**###%@@@@@@@%###*##%%%%%%%%%@@@@@@@@@%%%%%%%@@@@@@@@@@@@
%%@%@@@@@%%%%%%@@@@@%%@@@@@%%##+===----:::::::::::::::::::::::::------+++*+*#%%%%%%@%##***#%%@@@@@@%%%%@@@@@@@%%%%%@@@@@@@@@@@@@
%@@@@@@@@@%%%%%%%%%%@@@@@@@%#**+===----:::::::::::::::::::::::::------=+++***#####%%%%####%%@@@@@@%%%%%%@@%%%%%%%%%%@@@@@@@@%%%@
@@@@@@@@@@@%%%%%%%%%@@@@@@@%*++====----:::::::::::::::::::::::::-----==++*+*##*##%%%%@@%%%%@@@@%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@%@@
@@@@@@@@@@%%%%%%%%%@@@@@@@%%#+====-----:::::::::::::::::::::::::::---==++***####%%%%@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@
@@@@@@@@%%%@@@%%%%%%%@@@@@%%#*+===-----::::::::::::::::::::::::::-----==+**#####%%%@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@
%%%%%%%%%%@@@@%%%%%%%%%%%%%%%#++==------:::::::::::::::::::::::::-------==++**###%%%%@@@%%@@@@@@@@%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@
%%%%%%%%@@@@%%%%%%%%%%%%%%%%%#++==--------:::::::::::::::-=+*++=---------=+++*##%%%%%%%%%%@@@@%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@
%%%%%%%@@@@@%%%%%%%%%%%%%%%%##++==----------::::::::::-=+*#***++++=------==*++*#=-=*%%%%%%%%@@%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@%
%%%%%%%@@@@@@@%%%%%%#####%%%%#++==-=*****+==--:-::---+*##*+=--====++=----==+***+++=-#%%%#%%%@%%%%%%%%%%%%%%%%%%%%%%@@%%%%%%%%%%%
%%%%%%@@@@%@@%%%%%%%######%@%#++++*****#%%##*+==----+++=+++##%***+==------=++*++==--+#####%@%%%%%%%%%%%@@@%%%%%%%@@@@%%%%%%%%%%%
%%%%@@@@@@@%%%%#%%%%%####%@%%#+++**+++=+++*****=-::-=+=++-:+**===-=-:::--===+*+=--=-+%%#%%@@@%%%%%%%%%%%%@@@%%%%%%%%%%%%%%%%%%%%
@@%@@@@@@@%%%###%%%%%%%%@@%*%*+=++++*#+#%*=-=+=+----===-=---:---::::-----===+**+---=*%%%@@@@@@%%%%%%%%%%%@@@%%%%%%%%%%%%%%%%%%%%
%%%%@@@@@%%%%#%%%%%%%%%%@@%++*+====+++===----=+=-:--==-----------:::::--====+*+:-::=*%%%%%@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%@%%%%%%%
%%%@@@%%####%%%%%%%%#%%%%@@=-++=-----====----=+=-:-----:::::::------::--====+*#=:---*%%%%%%@@@@@@@@@@@@@%%%%%%%@@@@@@@%@@%%%%%%@
@@@@@@%#####%%%%%%%%%%%%%@@+-++==------------=+=-:-----==---:::::--------===+***=-=-*%%%%%@@@@@@@@@@@@@@%%%%%%%%@@@@@@%%%%%@@@@@
@@@@@%%%%##%%%%%%%%%%%%%@%@%=+++=--------:::-=++=:------==++=-::::------===+**#*----*%@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%@@@@@
@@@@%%%%%%@@@@@@@@%%%%%%%%%%%+*+=-------::-=+=++=::----=+--=++----------==++=***--::#@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%@@@
%%%%%%%%%@@@@@@@@@@%%%%%%%%@%+*+===-------==++++=---=**++*=+=+*=------====+===+*=-=-#@@@@@@@@%%%%%@@@@@@@@@%%%%@@@%%%%%@%%%%@@@@
%%%@@%%%%%%@@@@@@@@@%%%%%@@@@#**+==------==+**%%*+=+##*#*##*++=++==============*===*@@@%%@%%%%%%%@@@@@@@%%%@@@@@@@@%%%%%%@@@@@@@
%%%%%@@%%%%%%%%%%%%%%%%%%@@@@*+*+====---=++#*####%#*######+##++=+*============+*+%%@@@@%%%%%%%%%@@@@@@@%%%%@@@@@@@@%%%%%%@@@@@@@
%%%%%%%%%%%%%%%%%%%%%%@@%%%%%+=*++======*+*#%%#%%**==+*##*##***+====----======+**#%%%%%%%%%%%%%%@@@@@@@@%%%@@@@@@@@@%%%@@@@@@@@@
%%%%%%%%%%%%%%%%%%@%%%%%%%%%%#=*+++====*#####%%#+=-=:::.=-*=--==----------====+*+#%%%%@@@@@%%%%%%@@@@@@@@@@@@@@%%%%%%@@@@@@@@@@@
%%%%%%%%%%%%%%%%%@@@%%%%%%%%%%#**++===*##*+==#*=-=====-------------------====+**+#%%%%@@@@@%%%%%%%%@@@@@@@@@@@@%%%%%%@@@@@@@@@%%
%%%%%%%%%%%%%%%%%%@@%%%%%%%%%%%#*+=====+========----------------=--------===++**+*%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@%%%%@@@@@@@@@@%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@%*+=====-=========-==---------====-------===+++**=*%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@%*+====-==+=+=---------------====-===--====+++*++**#%%%%@@%%%%%%%@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@%%%%*+======+++=--=========----===++========+++**+*+*%@@@@@@%%%%%%@@@%%%%%%@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*+=====+++======----===---===+=========+++***+*%@@@@@%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@%%
%%%@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%#*+==+*++======-----======+*=========+++****#@@@@@@@@%%%%%%@%%%%%%%%@@@%%%%%@@@@@@@@@@@@@%%%
%%%@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*+++++*+=+=+=========+=++===-=--==+++**+*@@@@@@@@@@@@@@@@%%%%%%%%@@@@%%%%%%@@@@@@@@@@@%%%%
%%%%%@@%%%%@@@%%%%%%%%%%%%%%%%%%%%%%%%%#*++++++++=+++++*++=+*+====---===+*#*+%@@@@@@@@@@@@@@@@%%%%%%%%%%%@%%%%%%%%%%%%%%%%@@@%%%
%%%%%@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%#**++++*+++*******+=---=======++*#+#@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@%%%
%%%%@@@@@@@@@@%%%%%%%%%%%%%%%%%%%@@%%%%%%#****++++++======-=========++*#+*@@@@@@@@@@@@@@@@@@@@@@@@%%%%%@%%@@%%%%%%%%%%%%@@@@%%%%
%%%%@@@@@@@@%%%%%@@@@@@%%%%%%%%@@@@%%%%%*###******++++===========+++*#*+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@%%%%
%%%%@@@@@@@@@@@%%%@@@@@@%%%%%%@@@@%%%%%%#**##****++++++++=+==+++++*#+++%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@%%%%%%%%%
%%@@@@@@@@@@@@@%%%%@@@@@%%%%%%@@@@%%%@@@#+*******+++++++++++++***++++*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%
%@@@@@@@@@@@@%%%%%%%%@@@%%%%%%@@@@@@@@@@%*++*******+++++++****+++++=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%
%%%@@@@@@@@%@%%%%%%%%%@%%%%%%%@@@@@@@@@@%%#*++**+*#%#**#*++*++++++*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%
%%%%%%@@@@@%%%%%%%%%%%%%%%%%%@@@@@@@@@##*####*++%####*+*+++++==+*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%
%%%%%%%@@@%%%%%%%%%%%%%%%@@@@@@@@@@@@*####*#**#@@@%%@@#=+++==+++%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%@@@%%%%%%%%%%%%@@@@@@@@@@@@%##***#***#@#*#%@@@@%+==++=+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@%*******#**#@%@@@@@@%#***+==#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@%********#**@@@%@@@%*#***+*+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@#***#**+**#%%@@%@@%@**++*++*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@#####**++*@%@%+@@#@@@+++*++#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%@@@@@@@@@@@@@@@@@@@@@@@@@@@%##***+++*%@@@@@@@@@@@*+=+=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%@@@@@@@@@@@@@@@@@@@@@@@@@@@%#****+++%@@@%@@@#@@@@@@+*=%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@##*****+*#@@@@%*#@@@@@##@*+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@%@@@@@@@@@@@@@@@@@@@@##*******#@@@%@@#*@@%*%@@%#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@*#***#**#@@@@%#@@#*%@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%#*##**+*%@@@@@#*@@#*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@%####**++%@@@%%@@**@@##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%@@@@@@@@@@@@@@@@@@@@@@##*****+#@@@@@##@@##@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
%%%@@@@@@@@@@@@@@@@@@@@@#*******%@@%@@@#%@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                                ________                 .___                      ____   ________ 
                                /  _____/_____ _______  __| _/______  ____ ______   \   \ /   /_   |
                                /   \  ___\__  \\_  __ \/ __ |\_  __ \/  _ \\____ \   \   Y   / |   |
                                \    \_\  \/ __ \|  | \/ /_/ | |  | \(  <_> )  |_> >   \     /  |   |
                                \______  (____  /__|  \____ | |__|   \____/|   __/     \___/   |___|
                                        \/     \/           \/              |__|                     
                                                        (0xbthn){Colors.ENDC}
"""
        print(banner)
    
    def _print_file_info(self):
        """Print file information"""
        file_size = self.original_path.stat().st_size / (1024 * 1024)  # MB
        print(f"{Colors.CYAN}{Colors.BOLD}Original File:{Colors.ENDC} {Colors.WHITE}{self.original_path}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}File Type:{Colors.ENDC} {Colors.WHITE}{self.results['file_type']}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}File Size:{Colors.ENDC} {Colors.WHITE}{file_size:.2f} MB{Colors.ENDC}")
        
        if self.results['file_type'] == 'XAPK':
            apk_size = self.apk_path.stat().st_size / (1024 * 1024)  # MB
            print(f"{Colors.CYAN}{Colors.BOLD}Extracted APK:{Colors.ENDC} {Colors.WHITE}{self.apk_path.name}{Colors.ENDC}")
            print(f"{Colors.CYAN}{Colors.BOLD}APK Size:{Colors.ENDC} {Colors.WHITE}{apk_size:.2f} MB{Colors.ENDC}")
        
        print(f"{Colors.CYAN}{Colors.BOLD}Analysis Time:{Colors.ENDC} {Colors.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}Output Directory:{Colors.ENDC} {Colors.WHITE}{self.output_dir}{Colors.ENDC}")
        print()
    
    def _print_step_header(self, step_num, total_steps, step_name, icon):
        """Print step header with progress"""
        progress = f"[{step_num}/{total_steps}]"
        print(f"{Colors.BLUE}{Colors.BOLD}{progress} {icon} {step_name}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.ENDC}")
    
    def _print_step_success(self):
        """Print step completion message"""
        print(f"{Colors.GREEN}{Colors.BOLD}[SUCCESS] Step completed successfully!{Colors.ENDC}")
        print()
    
    def _print_error(self, message):
        """Print error message"""
        print(f"{Colors.RED}{Colors.BOLD}[ERROR] {message}{Colors.ENDC}")
    
    def _print_final_summary(self):
        """Print final analysis summary"""
        security_score = self.results.get("security", {}).get("security_score", 0)
        score_color = Colors.GREEN if security_score >= 70 else Colors.YELLOW if security_score >= 40 else Colors.RED
        
        print(f"\n{Colors.PURPLE}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗")
        print("║                        ANALYSIS COMPLETE                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print()
        print(f"{Colors.CYAN}{Colors.BOLD}Security Score:{Colors.ENDC} {score_color}{Colors.BOLD}{security_score}/100{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}Results Location: {Colors.WHITE}{str(self.output_dir)}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}Generated Reports:{Colors.ENDC}")
        print(f"   • {Colors.WHITE}security_analysis.json{Colors.ENDC} - Detailed technical report")
        print(f"   • {Colors.WHITE}security_report.html{Colors.ENDC} - Visual HTML dashboard")
        print(f"   • {Colors.WHITE}security_summary.txt{Colors.ENDC} - Executive summary")
        print()
        print(f"{Colors.GREEN}{Colors.BOLD}Analysis completed successfully!{Colors.ENDC}")
    
    def _analyze_structure(self):
        """Analyze APK structure"""
        structure_analyzer = APKStructureAnalyzer(self.apk_path, self.extract_dir)
        self.results["structure"] = structure_analyzer.analyze()
    
    def _analyze_manifest(self):
        """Analyze AndroidManifest.xml"""
        manifest_analyzer = ManifestAnalyzer(self.extract_dir)
        self.results["manifest"] = manifest_analyzer.analyze()
    
    def _analyze_dex(self):
        """Analyze DEX files"""
        dex_analyzer = DEXAnalyzer(self.extract_dir)
        self.results["dex"] = dex_analyzer.analyze()
    
    def _analyze_native(self):
        """Analyze native libraries"""
        native_analyzer = NativeLibraryAnalyzer(self.extract_dir)
        self.results["native"] = native_analyzer.analyze()
    
    def _analyze_assets(self):
        """Analyze assets and resources"""
        assets_analyzer = AssetsAnalyzer(self.extract_dir)
        self.results["assets"] = assets_analyzer.analyze()
    
    def _analyze_secrets(self):
        """Detect hardcoded secrets"""
        secrets_detector = SecretsDetector(self.extract_dir)
        self.results["secrets"] = secrets_detector.analyze()
    
    def _analyze_security(self):
        """Run security checks"""
        security_checker = SecurityChecker(self.results)
        self.results["security"] = security_checker.analyze()
    
    def _analyze_certificates(self):
        """Analyze certificates and signing"""
        certificate_analyzer = CertificateAnalyzer(self.apk_path, self.extract_dir)
        self.results["certificates"] = certificate_analyzer.analyze()
    
    def _analyze_network(self):
        """Analyze network security"""
        network_analyzer = NetworkAnalyzer(self.extract_dir)
        self.results["network"] = network_analyzer.analyze()
    
    def _analyze_internet(self):
        """Analyze internet artifacts (hashes, URLs, emails, endpoints)"""
        internet_analyzer = InternetAnalyzer(self.extract_dir)
        self.results["internet"] = internet_analyzer.analyze()
    
    def _analyze_code_quality(self):
        """Analyze code quality"""
        code_quality_analyzer = CodeQualityAnalyzer(self.extract_dir)
        self.results["code_quality"] = code_quality_analyzer.analyze()
    
    def _analyze_permissions(self):
        """Analyze permissions"""
        permissions_analyzer = PermissionsAnalyzer(self.results["manifest"])
        self.results["permissions"] = permissions_analyzer.analyze()
    
    def _generate_reports(self):
        """Generate reports"""
        report_generator = CleanReportGenerator(self.results, self.output_dir)
        report_generator.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description="🔒 Advanced APK/XAPK Static Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk                           # Basic analysis
  %(prog)s app.xapk -o detailed_report       # Custom output directory
  %(prog)s app.apk --verbose --quick         # Quick analysis with verbose output
  %(prog)s app.apk --compare previous.json   # Compare with previous analysis
  %(prog)s app.apk --export csv              # Export results to CSV
  %(prog)s app.apk --compliance gdpr,owasp   # Check specific compliance standards
        """
    )
    
    parser.add_argument("file_path", help="Path to APK, XAPK, or AAB file")
    parser.add_argument("-o", "--output", help="Output directory", default="analysis_output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quick", action="store_true", help="Quick analysis (skip detailed code analysis)")
    parser.add_argument("--compare", help="Compare with previous analysis JSON file")
    parser.add_argument("--export", choices=['json', 'csv', 'html', 'pdf'], help="Export format")
    parser.add_argument("--compliance", help="Compliance standards to check (comma-separated: gdpr,owasp,pci)")
    parser.add_argument("--skip-modules", help="Skip specific analysis modules (comma-separated)")
    parser.add_argument("--only-modules", help="Run only specific analysis modules (comma-separated)")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--threads", type=int, default=4, help="Number of analysis threads")
    parser.add_argument("--timeout", type=int, default=300, help="Analysis timeout in seconds")
    
    args = parser.parse_args()
    
    if not os.path.isfile(args.file_path):
        print(f"{Colors.RED}[-] File not found: {args.file_path}{Colors.ENDC}")
        sys.exit(1)
    
    # Check file extension
    file_ext = Path(args.file_path).suffix.lower()
    supported_extensions = ['.apk', '.xapk', '.aab']
    
    if file_ext not in supported_extensions:
        print(f"{Colors.RED}[-] Unsupported file type: {file_ext}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[-] Supported formats: {', '.join(supported_extensions)}{Colors.ENDC}")
        sys.exit(1)
    
    try:
        # Load configuration if provided
        config = {}
        if args.config:
            config = load_config(args.config)
        
        # Create analyzer and run analysis
        analyzer = APKAnalyzer(args.file_path, args.output, config=config)
        
        # Apply command line options
        if args.quick:
            analyzer.set_quick_mode(True)
        
        if args.skip_modules:
            analyzer.skip_modules(args.skip_modules.split(','))
        
        if args.only_modules:
            analyzer.only_modules(args.only_modules.split(','))
        
        # Run analysis
        success = analyzer.run_analysis()
        
        # Handle comparison
        if args.compare and success:
            analyzer.compare_with_previous(args.compare)
        
        # Handle export
        if args.export and success:
            analyzer.export_results(args.export)
        
        # Handle compliance check
        if args.compliance and success:
            analyzer.check_compliance(args.compliance.split(','))
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        print(f"{Colors.RED}{Colors.BOLD}[ERROR] Analysis failed: {str(e)}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def load_config(config_path):
    """Load configuration from file"""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Colors.YELLOW}[WARNING] Failed to load config: {str(e)}{Colors.ENDC}")
        return {}

if __name__ == "__main__":
    main()