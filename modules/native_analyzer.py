#!/usr/bin/env python3
"""
Native Library Analyzer
Analyzes native libraries (.so files) in APK
"""

import os
import subprocess
from pathlib import Path

class NativeLibraryAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze native libraries"""
        results = {
            "has_native_libs": False,
            "architectures": [],
            "libraries": [],
            "total_size": 0,
            "security_features": {},
            "exported_functions": [],
            "imported_functions": [],
            "strings": [],
            "errors": []
        }
        
        try:
            lib_dir = self.extract_dir / "lib"
            
            if not lib_dir.exists():
                return results
            
            results["has_native_libs"] = True
            
            # Analyze each architecture
            for arch_dir in lib_dir.iterdir():
                if arch_dir.is_dir():
                    arch_info = self._analyze_architecture(arch_dir)
                    results["architectures"].append(arch_info)
                    results["total_size"] += arch_info["total_size"]
                    
                    # Collect all libraries
                    results["libraries"].extend(arch_info["libraries"])
            
        except Exception as e:
            results["errors"].append(f"Native library analysis error: {str(e)}")
            
        return results
    
    def _analyze_architecture(self, arch_dir):
        """Analyze libraries for specific architecture"""
        arch_info = {
            "name": arch_dir.name,
            "libraries": [],
            "total_size": 0,
            "library_count": 0
        }
        
        try:
            for so_file in arch_dir.glob("*.so"):
                lib_info = self._analyze_library(so_file)
                arch_info["libraries"].append(lib_info)
                arch_info["total_size"] += lib_info["size"]
                arch_info["library_count"] += 1
                
        except Exception as e:
            arch_info["error"] = str(e)
            
        return arch_info
    
    def _analyze_library(self, so_file):
        """Analyze individual .so library"""
        lib_info = {
            "name": so_file.name,
            "size": so_file.stat().st_size,
            "architecture": "",
            "security_features": {
                "nx": False,
                "stack_canary": False,
                "relro": False,
                "pie": False,
                "fortify": False
            },
            "exported_symbols": [],
            "imported_symbols": [],
            "strings": [],
            "errors": []
        }
        
        try:
            # Get file information
            lib_info["architecture"] = self._get_architecture(so_file)
            
            # Check security features
            lib_info["security_features"] = self._check_security_features(so_file)
            
            # Extract symbols
            lib_info["exported_symbols"] = self._extract_exported_symbols(so_file)
            lib_info["imported_symbols"] = self._extract_imported_symbols(so_file)
            
            # Extract strings
            lib_info["strings"] = self._extract_strings(so_file)
            
        except Exception as e:
            lib_info["errors"].append(f"Library analysis error: {str(e)}")
            
        return lib_info
    
    def _get_architecture(self, so_file):
        """Get library architecture using file command"""
        try:
            result = subprocess.run(['file', str(so_file)], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'aarch64' in output or 'arm64' in output:
                    return 'arm64-v8a'
                elif 'arm' in output:
                    return 'armeabi-v7a'
                elif 'x86-64' in output or 'x86_64' in output:
                    return 'x86_64'
                elif 'x86' in output:
                    return 'x86'
                else:
                    return 'unknown'
        except:
            pass
        return 'unknown'
    
    def _check_security_features(self, so_file):
        """Check security features in binary"""
        features = {
            "nx": False,
            "stack_canary": False,
            "relro": False,
            "pie": False,
            "fortify": False
        }
        
        try:
            # Use readelf to check security features
            result = subprocess.run(['readelf', '-h', '-l', '-d', str(so_file)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for NX bit (non-executable stack)
                if 'GNU_STACK' in output and 'RWE' not in output:
                    features["nx"] = True
                
                # Check for stack canary
                if '__stack_chk_fail' in output:
                    features["stack_canary"] = True
                
                # Check for RELRO
                if 'GNU_RELRO' in output:
                    features["relro"] = True
                
                # Check for PIE
                if 'DYN' in output and 'EXEC' not in output:
                    features["pie"] = True
                
                # Check for FORTIFY
                if any(func in output for func in ['__sprintf_chk', '__strcpy_chk', '__memcpy_chk']):
                    features["fortify"] = True
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
            
        return features
    
    def _extract_exported_symbols(self, so_file):
        """Extract exported symbols"""
        symbols = []
        try:
            # Use nm to extract symbols
            result = subprocess.run(['nm', '-D', str(so_file)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 3 and parts[1] in ['T', 'D', 'B']:
                            symbols.append(parts[2])
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Try objdump as alternative
            try:
                result = subprocess.run(['objdump', '-T', str(so_file)], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'DF' in line or 'DO' in line:
                            parts = line.strip().split()
                            if len(parts) >= 6:
                                symbols.append(parts[-1])
            except:
                pass
                
        return symbols[:100]  # Limit to prevent excessive data
    
    def _extract_imported_symbols(self, so_file):
        """Extract imported symbols"""
        symbols = []
        try:
            # Use readelf to extract dynamic symbols
            result = subprocess.run(['readelf', '-s', str(so_file)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'UND' in line and '@' in line:
                        parts = line.strip().split()
                        if len(parts) >= 8:
                            symbol = parts[7].split('@')[0]
                            if symbol:
                                symbols.append(symbol)
                                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
            
        return symbols[:100]  # Limit to prevent excessive data
    
    def _extract_strings(self, so_file):
        """Extract readable strings from binary"""
        strings = []
        try:
            result = subprocess.run(['strings', '-n', '4', str(so_file)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                all_strings = result.stdout.split('\n')
                
                # Filter interesting strings
                interesting_strings = []
                for s in all_strings:
                    s = s.strip()
                    if len(s) >= 4:
                        # Look for URLs, file paths, function names, etc.
                        if any(keyword in s.lower() for keyword in 
                              ['http', 'https', 'ftp', '.so', '.dll', 'lib', 
                               'android', 'java', 'jni', 'native']):
                            interesting_strings.append(s)
                        elif s.startswith('/') and len(s) > 5:  # File paths
                            interesting_strings.append(s)
                        elif any(c.isupper() for c in s) and len(s) > 6:  # Function names
                            interesting_strings.append(s)
                
                strings = interesting_strings[:50]  # Limit output
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
            
        return strings