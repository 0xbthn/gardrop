#!/usr/bin/env python3
"""
APK Structure Analyzer
Analyzes APK file structure and validity
"""

import os
import subprocess
import zipfile
from pathlib import Path

class APKStructureAnalyzer:
    def __init__(self, apk_path, extract_dir):
        self.apk_path = Path(apk_path)
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze APK file structure"""
        results = {
            "file_exists": False,
            "file_readable": False,
            "file_size": 0,
            "is_valid_zip": False,
            "can_extract": False,
            "contents": [],
            "structure": {},
            "errors": []
        }
        
        try:
            # Clean extract directory before analysis
            self._clean_extract_dir()
            
            # Check if APK exists and is readable
            if self.apk_path.exists():
                results["file_exists"] = True
                results["file_size"] = self.apk_path.stat().st_size
                
                if os.access(self.apk_path, os.R_OK):
                    results["file_readable"] = True
                
            # Test if APK is a valid ZIP file
            if results["file_readable"]:
                results["is_valid_zip"] = self._test_zip_integrity()
                
            # Extract APK contents
            if results["is_valid_zip"]:
                results["can_extract"] = self._extract_apk()
                
            # Analyze extracted contents
            if results["can_extract"]:
                results["contents"] = self._list_contents()
                results["structure"] = self._analyze_structure()
                
        except Exception as e:
            results["errors"].append(f"Analysis error: {str(e)}")
            
        return results
    
    def _test_zip_integrity(self):
        """Test APK ZIP integrity"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_file:
                # Test the ZIP file
                bad_file = zip_file.testzip()
                return bad_file is None
        except zipfile.BadZipFile:
            return False
        except Exception:
            return False
    
    def _extract_apk(self):
        """Extract APK contents"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_file:
                zip_file.extractall(self.extract_dir)
            return True
        except Exception:
            return False
    
    def _list_contents(self):
        """List all files in extracted APK"""
        contents = []
        try:
            for root, dirs, files in os.walk(self.extract_dir):
                for file in files:
                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(self.extract_dir)
                    
                    # Skip system files and hidden files
                    if file.startswith('.') or file.startswith('__'):
                        continue
                    
                    file_info = {
                        "path": str(rel_path),
                        "size": full_path.stat().st_size,
                        "type": self._get_file_type(full_path)
                    }
                    contents.append(file_info)
        except Exception as e:
            # Log error but don't fail completely
            print(f"Warning: Error listing contents: {e}")
            
        return contents
    
    def _analyze_structure(self):
        """Analyze APK directory structure"""
        structure = {
            "has_manifest": False,
            "has_dex": False,
            "has_resources": False,
            "has_assets": False,
            "has_native_libs": False,
            "has_meta_inf": False,
            "dex_files": [],
            "native_architectures": [],
            "important_files": []
        }
        
        try:
            # Check for AndroidManifest.xml
            manifest_path = self.extract_dir / "AndroidManifest.xml"
            structure["has_manifest"] = manifest_path.exists()
            if structure["has_manifest"]:
                structure["important_files"].append("AndroidManifest.xml")
            
            # Check for DEX files
            for dex_file in self.extract_dir.glob("*.dex"):
                structure["has_dex"] = True
                structure["dex_files"].append(dex_file.name)
                structure["important_files"].append(dex_file.name)
            
            # Check for resources
            res_dir = self.extract_dir / "res"
            structure["has_resources"] = res_dir.exists()
            
            # Check for assets
            assets_dir = self.extract_dir / "assets"
            structure["has_assets"] = assets_dir.exists()
            
            # Check for native libraries
            lib_dir = self.extract_dir / "lib"
            if lib_dir.exists():
                structure["has_native_libs"] = True
                for arch_dir in lib_dir.iterdir():
                    if arch_dir.is_dir():
                        structure["native_architectures"].append(arch_dir.name)
            
            # Check for META-INF
            meta_inf_dir = self.extract_dir / "META-INF"
            structure["has_meta_inf"] = meta_inf_dir.exists()
            
            # Look for other important files (more specific patterns)
            important_patterns = [
                "*.json",  # Config files
                "AndroidManifest.xml",  # Manifest
                "*.properties",  # Properties
                "lib/*.so"  # Native libraries
            ]
            
            for pattern in important_patterns:
                for file_path in self.extract_dir.rglob(pattern):
                    rel_path = file_path.relative_to(self.extract_dir)
                    rel_str = str(rel_path)
                    
                    # Skip common non-important files
                    skip_patterns = [
                        "res/values/",  # Resource files (too many)
                        "META-INF/",    # Meta files
                        "__pycache__/", # Python cache
                        ".DS_Store",    # Mac files
                        "Thumbs.db"     # Windows files
                    ]
                    
                    if any(skip in rel_str for skip in skip_patterns):
                        continue
                        
                    if rel_str not in structure["important_files"]:
                        structure["important_files"].append(rel_str)
                        
        except Exception as e:
            print(f"Warning: Error analyzing structure: {e}")
            
        return structure
    
    def _clean_extract_dir(self):
        """Clean extract directory before analysis"""
        try:
            if self.extract_dir.exists():
                import shutil
                shutil.rmtree(self.extract_dir)
            self.extract_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not clean extract directory: {e}")
    
    def _get_file_type(self, file_path):
        """Get file type using file command or extension"""
        try:
            # Try using file command first
            result = subprocess.run(['file', '-b', str(file_path)], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        
        # Fallback to extension-based detection
        try:
            extension = file_path.suffix.lower()
            extension_map = {
                '.dex': 'Dalvik executable',
                '.so': 'Shared object',
                '.xml': 'XML document',
                '.json': 'JSON data',
                '.properties': 'Properties file',
                '.png': 'PNG image',
                '.jpg': 'JPEG image',
                '.jpeg': 'JPEG image',
                '.gif': 'GIF image',
                '.webp': 'WebP image',
                '.mp3': 'MP3 audio',
                '.mp4': 'MP4 video',
                '.txt': 'Text file',
                '.html': 'HTML document',
                '.css': 'CSS stylesheet',
                '.js': 'JavaScript file',
                '.jar': 'Java archive',
                '.zip': 'ZIP archive',
                '.apk': 'Android package'
            }
            return extension_map.get(extension, 'unknown')
        except Exception:
            return "unknown"