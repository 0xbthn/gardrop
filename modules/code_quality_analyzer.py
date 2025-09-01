#!/usr/bin/env python3
"""
Code Quality Analyzer
Analyzes code quality, complexity, and potential issues
"""

import re
import os
from pathlib import Path
from collections import defaultdict

class CodeQualityAnalyzer:
    def __init__(self, extract_dir):
        self.extract_dir = Path(extract_dir)
        
    def analyze(self):
        """Analyze code quality and complexity"""
        results = {
            "code_metrics": {},
            "complexity_analysis": {},
            "code_smells": [],
            "dead_code": [],
            "unused_resources": [],
            "code_duplication": {},
            "naming_conventions": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        
        try:
            # Analyze code metrics
            results["code_metrics"] = self._analyze_code_metrics()
            
            # Analyze complexity
            results["complexity_analysis"] = self._analyze_complexity()
            
            # Detect code smells
            results["code_smells"] = self._detect_code_smells()
            
            # Find dead code
            results["dead_code"] = self._find_dead_code()
            
            # Find unused resources
            results["unused_resources"] = self._find_unused_resources()
            
            # Analyze code duplication
            results["code_duplication"] = self._analyze_code_duplication()
            
            # Check naming conventions
            results["naming_conventions"] = self._check_naming_conventions()
            
            # Check for vulnerabilities
            results["vulnerabilities"] = self._check_code_vulnerabilities(results)
            
            # Generate recommendations
            results["recommendations"] = self._generate_code_recommendations(results)
            
        except Exception as e:
            results["vulnerabilities"].append(f"Code quality analysis error: {str(e)}")
            
        return results
    
    def _analyze_code_metrics(self):
        """Analyze basic code metrics"""
        metrics = {
            "total_files": 0,
            "total_lines": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "classes": 0,
            "methods": 0,
            "average_method_length": 0,
            "average_class_length": 0
        }
        
        file_count = 0
        total_lines = 0
        code_lines = 0
        comment_lines = 0
        blank_lines = 0
        class_count = 0
        method_count = 0
        method_lengths = []
        class_lengths = []
        
        # Analyze DEX/Smali files
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    file_count += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            
                        total_lines += len(lines)
                        
                        for line in lines:
                            line = line.strip()
                            
                            if not line:
                                blank_lines += 1
                            elif line.startswith('#'):
                                comment_lines += 1
                            else:
                                code_lines += 1
                                
                                # Count classes and methods
                                if line.startswith('.class'):
                                    class_count += 1
                                    class_lengths.append(len(lines))
                                elif line.startswith('.method'):
                                    method_count += 1
                                    method_lengths.append(self._get_method_length(lines, lines.index(line)))
                                    
                    except Exception:
                        continue
        
        metrics.update({
            "total_files": file_count,
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "blank_lines": blank_lines,
            "classes": class_count,
            "methods": method_count,
            "average_method_length": sum(method_lengths) / len(method_lengths) if method_lengths else 0,
            "average_class_length": sum(class_lengths) / len(class_lengths) if class_lengths else 0
        })
        
        return metrics
    
    def _get_method_length(self, lines, start_index):
        """Get the length of a method"""
        length = 0
        brace_count = 0
        started = False
        
        for i in range(start_index, len(lines)):
            line = lines[i].strip()
            
            if line.startswith('.method'):
                started = True
                brace_count = 0
                continue
                
            if started:
                if line.startswith('.end method'):
                    break
                    
                if '{' in line:
                    brace_count += line.count('{')
                if '}' in line:
                    brace_count -= line.count('}')
                    
                length += 1
                
        return length
    
    def _analyze_complexity(self):
        """Analyze code complexity"""
        complexity = {
            "cyclomatic_complexity": {},
            "nesting_depth": {},
            "method_complexity": {},
            "class_complexity": {}
        }
        
        # Analyze cyclomatic complexity
        complexity["cyclomatic_complexity"] = self._calculate_cyclomatic_complexity()
        
        # Analyze nesting depth
        complexity["nesting_depth"] = self._analyze_nesting_depth()
        
        return complexity
    
    def _calculate_cyclomatic_complexity(self):
        """Calculate cyclomatic complexity for methods"""
        complexity_data = {}
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Find methods and calculate complexity
                        method_pattern = r'\.method[^}]*?\.end method'
                        methods = re.findall(method_pattern, content, re.DOTALL)
                        
                        for method in methods:
                            method_name = self._extract_method_name(method)
                            complexity = self._calculate_method_complexity(method)
                            
                            if complexity > 10:  # High complexity threshold
                                complexity_data[method_name] = {
                                    "complexity": complexity,
                                    "file": str(file_path),
                                    "severity": "HIGH" if complexity > 15 else "MEDIUM"
                                }
                                
                    except Exception:
                        continue
        
        return complexity_data
    
    def _extract_method_name(self, method_content):
        """Extract method name from method content"""
        lines = method_content.split('\n')
        for line in lines:
            if line.strip().startswith('.method'):
                return line.strip()
        return "Unknown"
    
    def _calculate_method_complexity(self, method_content):
        """Calculate cyclomatic complexity for a method"""
        complexity = 1  # Base complexity
        
        # Count decision points
        decision_patterns = [
            r'if-',           # if statements
            r'goto',          # goto statements
            r'switch',        # switch statements
            r'case',          # case statements
            r'throw',         # exception throwing
            r'return'         # return statements
        ]
        
        for pattern in decision_patterns:
            matches = re.findall(pattern, method_content)
            complexity += len(matches)
        
        return complexity
    
    def _analyze_nesting_depth(self):
        """Analyze nesting depth in code"""
        nesting_data = {}
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            
                        max_depth = 0
                        current_depth = 0
                        
                        for line in lines:
                            line = line.strip()
                            
                            if line.startswith('if-') or line.startswith('switch'):
                                current_depth += 1
                                max_depth = max(max_depth, current_depth)
                            elif line.startswith('.end'):
                                current_depth = max(0, current_depth - 1)
                        
                        if max_depth > 3:  # High nesting threshold
                            nesting_data[str(file_path)] = {
                                "max_depth": max_depth,
                                "severity": "HIGH" if max_depth > 5 else "MEDIUM"
                            }
                            
                    except Exception:
                        continue
        
        return nesting_data
    
    def _detect_code_smells(self):
        """Detect common code smells"""
        code_smells = []
        
        # Long method smell
        code_smells.extend(self._detect_long_methods())
        
        # Large class smell
        code_smells.extend(self._detect_large_classes())
        
        # Duplicate code smell
        code_smells.extend(self._detect_duplicate_code())
        
        # Magic numbers
        code_smells.extend(self._detect_magic_numbers())
        
        # Dead code
        code_smells.extend(self._detect_dead_code_smells())
        
        return code_smells
    
    def _detect_long_methods(self):
        """Detect methods that are too long"""
        long_methods = []
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        method_pattern = r'\.method[^}]*?\.end method'
                        methods = re.findall(method_pattern, content, re.DOTALL)
                        
                        for method in methods:
                            lines = method.split('\n')
                            if len(lines) > 50:  # Long method threshold
                                method_name = self._extract_method_name(method)
                                long_methods.append({
                                    "type": "LONG_METHOD",
                                    "method": method_name,
                                    "file": str(file_path),
                                    "lines": len(lines),
                                    "severity": "MEDIUM"
                                })
                                
                    except Exception:
                        continue
        
        return long_methods
    
    def _detect_large_classes(self):
        """Detect classes that are too large"""
        large_classes = []
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            
                        if len(lines) > 500:  # Large class threshold
                            large_classes.append({
                                "type": "LARGE_CLASS",
                                "file": str(file_path),
                                "lines": len(lines),
                                "severity": "MEDIUM"
                            })
                            
                    except Exception:
                        continue
        
        return large_classes
    
    def _detect_duplicate_code(self):
        """Detect duplicate code blocks"""
        duplicates = []
        
        # This is a simplified implementation
        # In a real scenario, you'd use more sophisticated algorithms
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Look for repeated patterns
                        lines = content.split('\n')
                        for i in range(len(lines) - 5):
                            pattern = '\n'.join(lines[i:i+5])
                            if content.count(pattern) > 2:
                                duplicates.append({
                                    "type": "DUPLICATE_CODE",
                                    "file": str(file_path),
                                    "pattern": pattern[:100] + "...",
                                    "occurrences": content.count(pattern),
                                    "severity": "LOW"
                                })
                                
                    except Exception:
                        continue
        
        return duplicates
    
    def _detect_magic_numbers(self):
        """Detect magic numbers in code"""
        magic_numbers = []
        
        magic_number_patterns = [
            r'\b\d{4,}\b',  # Numbers with 4+ digits
            r'\b0x[0-9a-fA-F]{4,}\b'  # Large hex numbers
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern in magic_number_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                magic_numbers.append({
                                    "type": "MAGIC_NUMBER",
                                    "file": str(file_path),
                                    "number": match,
                                    "severity": "LOW"
                                })
                                
                    except Exception:
                        continue
        
        return magic_numbers
    
    def _detect_dead_code_smells(self):
        """Detect dead code patterns"""
        dead_code = []
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Look for unused methods (simplified)
                        if 'unused' in content.lower() or 'deprecated' in content.lower():
                            dead_code.append({
                                "type": "DEAD_CODE",
                                "file": str(file_path),
                                "description": "Potentially unused or deprecated code",
                                "severity": "LOW"
                            })
                            
                    except Exception:
                        continue
        
        return dead_code
    
    def _find_dead_code(self):
        """Find dead code in the application"""
        dead_code = []
        
        # This is a simplified implementation
        # In practice, you'd need more sophisticated static analysis
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Look for obvious dead code patterns
                        if 'unused' in content or 'deprecated' in content:
                            dead_code.append({
                                "file": str(file_path),
                                "type": "POTENTIAL_DEAD_CODE",
                                "description": "Code marked as unused or deprecated"
                            })
                            
                    except Exception:
                        continue
        
        return dead_code
    
    def _find_unused_resources(self):
        """Find unused resources"""
        unused_resources = []
        
        # Check for unused drawables, layouts, etc.
        resource_dirs = ['res/drawable', 'res/layout', 'res/values']
        
        for resource_dir in resource_dirs:
            resource_path = self.extract_dir / resource_dir
            if resource_path.exists():
                for file in resource_path.rglob('*'):
                    if file.is_file():
                        # Check if resource is referenced
                        if not self._is_resource_used(file):
                            unused_resources.append({
                                "file": str(file),
                                "type": "UNUSED_RESOURCE",
                                "description": "Resource file not referenced in code"
                            })
        
        return unused_resources
    
    def _is_resource_used(self, resource_file):
        """Check if a resource file is used in the codebase"""
        resource_name = resource_file.stem
        
        # Search for resource references
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if resource_name in content:
                                return True
                    except Exception:
                        continue
        
        return False
    
    def _analyze_code_duplication(self):
        """Analyze code duplication"""
        duplication = {
            "duplicate_blocks": [],
            "duplication_percentage": 0,
            "total_duplicate_lines": 0
        }
        
        # Simplified duplication analysis
        all_code_blocks = []
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            
                        # Extract code blocks (simplified)
                        for i in range(0, len(lines) - 5, 5):
                            block = ''.join(lines[i:i+5])
                            all_code_blocks.append((block, str(file_path)))
                            
                    except Exception:
                        continue
        
        # Find duplicates
        seen_blocks = {}
        for block, file_path in all_code_blocks:
            if block in seen_blocks:
                seen_blocks[block].append(file_path)
            else:
                seen_blocks[block] = [file_path]
        
        # Report duplicates
        for block, files in seen_blocks.items():
            if len(files) > 1:
                duplication["duplicate_blocks"].append({
                    "block": block[:100] + "...",
                    "files": files,
                    "occurrences": len(files)
                })
        
        return duplication
    
    def _check_naming_conventions(self):
        """Check naming conventions"""
        naming_issues = {
            "class_naming": [],
            "method_naming": [],
            "variable_naming": [],
            "constant_naming": []
        }
        
        # Check class naming (should be PascalCase)
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Find class declarations
                        class_pattern = r'\.class[^L]*L([^;]+);'
                        classes = re.findall(class_pattern, content)
                        
                        for class_name in classes:
                            if not self._is_pascal_case(class_name.split('/')[-1]):
                                naming_issues["class_naming"].append({
                                    "class": class_name,
                                    "file": str(file_path),
                                    "issue": "Class name should be PascalCase"
                                })
                                
                    except Exception:
                        continue
        
        return naming_issues
    
    def _is_pascal_case(self, name):
        """Check if a name follows PascalCase convention"""
        if not name:
            return False
        return name[0].isupper() and name.isalnum()
    
    def _check_code_vulnerabilities(self, results):
        """Check for code-related vulnerabilities"""
        vulnerabilities = []
        
        # Check for hardcoded credentials
        if self._has_hardcoded_credentials():
            vulnerabilities.append({
                "type": "HARDCODED_CREDENTIALS",
                "severity": "HIGH",
                "description": "Hardcoded credentials found in code",
                "impact": "Credentials exposed in application code"
            })
        
        # Check for SQL injection patterns
        if self._has_sql_injection_patterns():
            vulnerabilities.append({
                "type": "SQL_INJECTION_PATTERN",
                "severity": "MEDIUM",
                "description": "Potential SQL injection patterns detected",
                "impact": "Risk of SQL injection attacks"
            })
        
        # Check for weak encryption
        if self._has_weak_encryption():
            vulnerabilities.append({
                "type": "WEAK_ENCRYPTION",
                "severity": "HIGH",
                "description": "Weak encryption algorithms detected",
                "impact": "Data may be vulnerable to decryption"
            })
        
        return vulnerabilities
    
    def _has_hardcoded_credentials(self):
        """Check for hardcoded credentials"""
        credential_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.txt')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern in credential_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                return True
                                
                    except Exception:
                        continue
        
        return False
    
    def _has_sql_injection_patterns(self):
        """Check for SQL injection patterns"""
        sql_patterns = [
            r'SELECT.*WHERE.*\+',
            r'INSERT.*VALUES.*\+',
            r'UPDATE.*SET.*\+',
            r'DELETE.*WHERE.*\+'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern in sql_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                return True
                                
                    except Exception:
                        continue
        
        return False
    
    def _has_weak_encryption(self):
        """Check for weak encryption algorithms"""
        weak_encryption_patterns = [
            r'MD5',
            r'SHA1',
            r'DES',
            r'RC4'
        ]
        
        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern in weak_encryption_patterns:
                            if re.search(pattern, content):
                                return True
                                
                    except Exception:
                        continue
        
        return False
    
    def _generate_code_recommendations(self, results):
        """Generate code quality recommendations"""
        recommendations = []
        
        # Complexity recommendations
        if results["complexity_analysis"]["cyclomatic_complexity"]:
            recommendations.append("Refactor methods with high cyclomatic complexity")
        
        # Code smell recommendations
        if results["code_smells"]:
            recommendations.append("Address detected code smells")
        
        # Dead code recommendations
        if results["dead_code"]:
            recommendations.append("Remove dead code to improve maintainability")
        
        # Unused resources recommendations
        if results["unused_resources"]:
            recommendations.append("Remove unused resources to reduce APK size")
        
        # Naming convention recommendations
        if results["naming_conventions"]["class_naming"]:
            recommendations.append("Follow proper naming conventions for classes")
        
        return recommendations 