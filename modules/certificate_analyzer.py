#!/usr/bin/env python3
"""
Certificate Analyzer
Analyzes APK certificates and signing information
"""

import os
import subprocess
import zipfile
from pathlib import Path
from datetime import datetime

class CertificateAnalyzer:
    def __init__(self, apk_path, extract_dir):
        self.apk_path = Path(apk_path)
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze APK certificates and signing"""
        results = {
            "certificates": [],
            "signing_info": {},
            "signature_algorithm": "",
            "validity_period": {},
            "issuer_info": {},
            "subject_info": {},
            "fingerprints": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        
        try:
            # Extract certificates from APK
            cert_files = self._extract_certificates()
            
            # Analyze each certificate
            for cert_file in cert_files:
                cert_info = self._analyze_certificate(cert_file)
                results["certificates"].append(cert_info)
            
            # Analyze signing information
            results["signing_info"] = self._analyze_signing_info()
            
            # Check for vulnerabilities
            results["vulnerabilities"] = self._check_certificate_vulnerabilities(results)
            
            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(results)
            
        except Exception as e:
            results["vulnerabilities"].append(f"Certificate analysis error: {str(e)}")
            
        return results
    
    def _extract_certificates(self):
        """Extract certificate files from APK"""
        cert_files = []
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_file:
                # Look for certificate files
                for file_info in zip_file.filelist:
                    if file_info.filename.startswith('META-INF/') and file_info.filename.endswith('.RSA'):
                        cert_files.append(file_info.filename)
                    elif file_info.filename.startswith('META-INF/') and file_info.filename.endswith('.DSA'):
                        cert_files.append(file_info.filename)
                    elif file_info.filename.startswith('META-INF/') and file_info.filename.endswith('.EC'):
                        cert_files.append(file_info.filename)
                        
        except Exception as e:
            print(f"Error extracting certificates: {str(e)}")
            
        return cert_files
    
    def _analyze_certificate(self, cert_file):
        """Analyze individual certificate file"""
        cert_info = {
            "file": cert_file,
            "algorithm": "",
            "issuer": "",
            "subject": "",
            "valid_from": "",
            "valid_until": "",
            "serial_number": "",
            "fingerprint": "",
            "is_valid": False
        }
        
        try:
            # Use keytool to analyze certificate
            cmd = f"keytool -printcert -jarfile {self.apk_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                output = result.stdout
                cert_info.update(self._parse_keytool_output(output))
                
        except Exception as e:
            cert_info["error"] = str(e)
            
        return cert_info
    
    def _parse_keytool_output(self, output):
        """Parse keytool output to extract certificate information"""
        info = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if line.startswith('Owner:'):
                info["subject"] = line.replace('Owner:', '').strip()
            elif line.startswith('Issuer:'):
                info["issuer"] = line.replace('Issuer:', '').strip()
            elif line.startswith('Serial number:'):
                info["serial_number"] = line.replace('Serial number:', '').strip()
            elif line.startswith('Valid from:'):
                info["valid_from"] = line.replace('Valid from:', '').strip()
            elif line.startswith('Certificate fingerprints:'):
                # Parse fingerprint information
                pass
                
        return info
    
    def _analyze_signing_info(self):
        """Analyze APK signing information"""
        signing_info = {
            "v1_signing": False,
            "v2_signing": False,
            "v3_signing": False,
            "v4_signing": False,
            "signature_schemes": [],
            "apk_signer_version": ""
        }
        
        try:
            # Use apksigner to verify signing
            cmd = f"apksigner verify --verbose {self.apk_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                output = result.stdout
                signing_info.update(self._parse_apksigner_output(output))
                
        except Exception as e:
            signing_info["error"] = str(e)
            
        return signing_info
    
    def _parse_apksigner_output(self, output):
        """Parse apksigner output"""
        info = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if "Verified using v1 scheme" in line:
                info["v1_signing"] = True
            elif "Verified using v2 scheme" in line:
                info["v2_signing"] = True
            elif "Verified using v3 scheme" in line:
                info["v3_signing"] = True
            elif "Verified using v4 scheme" in line:
                info["v4_signing"] = True
                
        return info
    
    def _check_certificate_vulnerabilities(self, results):
        """Check for certificate-related vulnerabilities"""
        vulnerabilities = []
        
        # Check if APK is signed
        if not results["certificates"]:
            vulnerabilities.append({
                "type": "UNSIGNED_APK",
                "severity": "HIGH",
                "description": "APK is not signed with any certificate",
                "impact": "APK cannot be installed on devices with signature verification enabled"
            })
        
        # Check certificate expiration
        for cert in results["certificates"]:
            if cert.get("valid_until"):
                try:
                    valid_until = datetime.strptime(cert["valid_until"], "%a %b %d %H:%M:%S %Z %Y")
                    if valid_until < datetime.now():
                        vulnerabilities.append({
                            "type": "EXPIRED_CERTIFICATE",
                            "severity": "HIGH",
                            "description": f"Certificate expired on {cert['valid_until']}",
                            "impact": "APK cannot be installed or updated"
                        })
                except:
                    pass
        
        # Check for weak signature algorithms
        weak_algorithms = ["MD5", "SHA1"]
        for cert in results["certificates"]:
            if cert.get("algorithm") in weak_algorithms:
                vulnerabilities.append({
                    "type": "WEAK_SIGNATURE_ALGORITHM",
                    "severity": "MEDIUM",
                    "description": f"Certificate uses weak algorithm: {cert['algorithm']}",
                    "impact": "Vulnerable to signature forgery attacks"
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self, results):
        """Generate certificate-related recommendations"""
        recommendations = []
        
        if not results["certificates"]:
            recommendations.append("Sign the APK with a valid certificate")
        
        if results["vulnerabilities"]:
            for vuln in results["vulnerabilities"]:
                if vuln["type"] == "EXPIRED_CERTIFICATE":
                    recommendations.append("Renew the certificate before it expires")
                elif vuln["type"] == "WEAK_SIGNATURE_ALGORITHM":
                    recommendations.append("Use SHA-256 or stronger signature algorithm")
        
        if not results["signing_info"].get("v2_signing"):
            recommendations.append("Enable APK Signature Scheme v2 for better security")
        
        return recommendations 