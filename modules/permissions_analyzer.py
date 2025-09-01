#!/usr/bin/env python3
"""
Permissions Analyzer
Analyzes Android permissions and identifies security risks
"""

class PermissionsAnalyzer:
    def __init__(self, manifest_results):
        self.manifest_results = manifest_results
        
        # Define permission categories and risk levels (improved with context awareness)
        self.permission_categories = {
            "critical_risk": [
                "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG",
                "ACCESS_BACKGROUND_LOCATION", "BODY_SENSORS", "SYSTEM_ALERT_WINDOW"
            ],
            "high_risk": [
                "READ_CONTACTS", "WRITE_CONTACTS", "READ_PHONE_STATE", "CALL_PHONE",
                "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO", 
                "CAMERA", "READ_CALENDAR", "WRITE_CALENDAR"
            ],
            "medium_risk": [
                "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
                "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE",
                "BLUETOOTH", "BLUETOOTH_ADMIN", "NFC", "VIBRATE", "WAKE_LOCK",
                "GET_ACCOUNTS", "USE_CREDENTIALS", "AUTHENTICATE_ACCOUNTS"
            ],
            "low_risk": [
                "ACCESS_NOTIFICATION_POLICY", "EXPAND_STATUS_BAR", "FLASHLIGHT",
                "KILL_BACKGROUND_PROCESSES", "MODIFY_AUDIO_SETTINGS", "SET_WALLPAPER",
                "SET_WALLPAPER_HINTS", "USE_FINGERPRINT", "USE_BIOMETRIC", 
                "RECEIVE_BOOT_COMPLETED", "VIBRATE", "WAKE_LOCK"
            ],
            "development": [
                "WRITE_SECURE_SETTINGS", "WRITE_SETTINGS", "INSTALL_PACKAGES",
                "DELETE_PACKAGES", "CLEAR_APP_CACHE", "GET_PACKAGE_SIZE",
                "SET_DEBUG_APP", "DUMP", "READ_LOGS"
            ],
            "normal": [
                "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
                "VIBRATE", "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED"
            ]
        }
        
        # Define permission descriptions and risks
        self.permission_risks = {
            "READ_CONTACTS": {
                "description": "Read user's contacts",
                "risk": "Access to personal contact information",
                "justification_needed": True
            },
            "READ_SMS": {
                "description": "Read SMS messages",
                "risk": "Access to private messages and potential 2FA codes",
                "justification_needed": True
            },
            "ACCESS_FINE_LOCATION": {
                "description": "Access precise location",
                "risk": "Tracking user's exact location",
                "justification_needed": True
            },
            "CAMERA": {
                "description": "Access camera",
                "risk": "Potential privacy invasion through photo/video capture",
                "justification_needed": True
            },
            "RECORD_AUDIO": {
                "description": "Record audio",
                "risk": "Potential eavesdropping on conversations",
                "justification_needed": True
            },
            "READ_CALL_LOG": {
                "description": "Read call history",
                "risk": "Access to communication patterns and contacts",
                "justification_needed": True
            },
            "INTERNET": {
                "description": "Full network access",
                "risk": "Data exfiltration and communication with external servers",
                "justification_needed": False
            },
            "WRITE_EXTERNAL_STORAGE": {
                "description": "Modify or delete storage contents",
                "risk": "Potential data corruption or malware installation",
                "justification_needed": False
            }
        }
        
    def analyze(self):
        """Analyze permissions for security risks"""
        results = {
            "total_permissions": 0,
            "dangerous_permissions": [],
            "normal_permissions": [],
            "custom_permissions": [],
            "permission_analysis": {
                "high_risk": [],
                "medium_risk": [],
                "low_risk": [],
                "development": [],
                "unknown": []
            },
            "risk_assessment": {
                "overall_risk": "low",
                "risk_score": 0,
                "major_concerns": [],
                "unnecessary_permissions": []
            },
            "permission_combinations": [],
            "recommendations": [],
            "detailed_analysis": []
        }
        
        try:
            permissions = self.manifest_results.get("permissions", [])
            dangerous_perms = self.manifest_results.get("dangerous_permissions", [])
            
            results["total_permissions"] = len(permissions)
            results["dangerous_permissions"] = dangerous_perms
            
            # Categorize permissions
            self._categorize_permissions(permissions, results)
            
            # Analyze risk combinations
            results["permission_combinations"] = self._analyze_permission_combinations(dangerous_perms)
            
            # Assess overall risk
            results["risk_assessment"] = self._assess_overall_risk(permissions, dangerous_perms)
            
            # Generate detailed analysis
            results["detailed_analysis"] = self._generate_detailed_analysis(permissions)
            
            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(results)
            
        except Exception as e:
            results["error"] = f"Permission analysis error: {str(e)}"
            
        return results
    
    def _categorize_permissions(self, permissions, results):
        """Categorize permissions by risk level"""
        for permission in permissions:
            # Extract permission name (remove android.permission. prefix)
            perm_name = permission.split('.')[-1] if '.' in permission else permission
            
            categorized = False
            for category, perm_list in self.permission_categories.items():
                if any(risk_perm in perm_name for risk_perm in perm_list):
                    results["permission_analysis"][category].append(permission)
                    categorized = True
                    break
            
            if not categorized:
                if permission.startswith("android.permission."):
                    # Standard Android permission but not in our lists
                    results["permission_analysis"]["unknown"].append(permission)
                else:
                    # Custom permission
                    results["custom_permissions"].append(permission)
    
    def _analyze_permission_combinations(self, dangerous_permissions):
        """Analyze dangerous permission combinations with improved context awareness"""
        combinations = []
        
        # Define risky permission combinations with better context
        risky_combinations = [
            {
                "name": "SMS + Network",
                "permissions": ["READ_SMS", "INTERNET"],
                "risk": "SMS content exfiltration and 2FA bypass",
                "severity": "critical",
                "context": "Legitimate for SMS apps, banking apps, or 2FA services"
            },
            {
                "name": "Call Log + Network", 
                "permissions": ["READ_CALL_LOG", "INTERNET"],
                "risk": "Call history exfiltration",
                "severity": "critical",
                "context": "Legitimate for call recording apps or communication services"
            },
            {
                "name": "Location + Network",
                "permissions": ["ACCESS_FINE_LOCATION", "INTERNET"],
                "risk": "Location tracking and data exfiltration",
                "severity": "high",
                "context": "Legitimate for navigation, ride-sharing, or location-based services"
            },
            {
                "name": "Camera + Network",
                "permissions": ["CAMERA", "INTERNET"],
                "risk": "Photo/video capture and upload",
                "severity": "high", 
                "context": "Legitimate for social media, video calling, or photo sharing apps"
            },
            {
                "name": "Microphone + Network",
                "permissions": ["RECORD_AUDIO", "INTERNET"],
                "risk": "Audio recording and upload",
                "severity": "high",
                "context": "Legitimate for voice calling, recording, or audio messaging apps"
            },
            {
                "name": "Contacts + Network",
                "permissions": ["READ_CONTACTS", "INTERNET"],
                "risk": "Contact list exfiltration",
                "severity": "medium",
                "context": "Legitimate for messaging, social media, or contact sync apps"
            },
            {
                "name": "Storage + Network",
                "permissions": ["READ_EXTERNAL_STORAGE", "INTERNET"],
                "risk": "File system access and data exfiltration",
                "severity": "medium",
                "context": "Legitimate for file sharing, backup, or cloud storage apps"
            },
            {
                "name": "Multiple High-Risk Permissions",
                "permissions": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"],
                "risk": "Comprehensive surveillance capabilities",
                "severity": "critical",
                "context": "Legitimate for security apps, video conferencing, or AR applications"
            },
            {
                "name": "Admin Privileges",
                "permissions": ["DEVICE_ADMIN", "INTERNET"],
                "risk": "Device control and remote administration",
                "severity": "critical",
                "context": "Legitimate for MDM, security, or device management apps"
            }
        ]
        
        # Check combinations with context awareness
        for combo in risky_combinations:
            if all(any(perm in dangerous_perm for perm in combo["permissions"]) 
                   for dangerous_perm in dangerous_permissions):
                
                # Add context information to help reduce false positives
                combo_with_context = combo.copy()
                combinations.append(combo_with_context)
        
        return combinations
    
    def _assess_overall_risk(self, all_permissions, dangerous_permissions):
        """Assess overall permission risk with improved context awareness"""
        risk_assessment = {
            "overall_risk": "low",
            "risk_score": 0,
            "major_concerns": [],
            "unnecessary_permissions": [],
            "context_notes": []
        }
        
        # Calculate risk score with balanced weighting
        risk_score = 0
        
        # Critical-risk permissions (reduced weight)
        critical_risk_count = len([p for p in dangerous_permissions 
                                  if any(cr in p for cr in self.permission_categories.get("critical_risk", []))])
        risk_score += critical_risk_count * 8  # Reduced from 20
        
        # High-risk permissions (reduced weight)
        high_risk_count = len([p for p in dangerous_permissions 
                              if any(hr in p for hr in self.permission_categories.get("high_risk", []))])
        risk_score += high_risk_count * 4  # Reduced from 10
        
        # Medium-risk permissions (reduced weight)
        medium_risk_count = len([p for p in all_permissions 
                                if any(mr in p for mr in self.permission_categories.get("medium_risk", []))])
        risk_score += medium_risk_count * 2  # Reduced from 5
        
        # Development permissions in production (reduced weight)
        dev_perms = [p for p in all_permissions 
                    if any(dp in p for dp in self.permission_categories.get("development", []))]
        if dev_perms:
            risk_score += len(dev_perms) * 10  # Reduced from 25
            risk_assessment["major_concerns"].append(
                f"Development permissions found: {', '.join(dev_perms)}"
            )
        
        # Context-aware analysis
        # Check for legitimate app types that might need multiple permissions
        app_context = self._analyze_app_context(all_permissions)
        
        # Adjust risk based on app context
        if app_context["likely_legitimate"]:
            risk_score = max(0, risk_score - 15)  # Reduced from 20
            risk_assessment["context_notes"].append(
                f"App appears to be {app_context['app_type']} - some permissions may be legitimate"
            )
        
        # Too many dangerous permissions (much more lenient)
        if len(dangerous_permissions) > 15:  # Increased threshold
            risk_score += (len(dangerous_permissions) - 15) * 1  # Reduced multiplier
            risk_assessment["major_concerns"].append(
                f"Very high number of dangerous permissions: {len(dangerous_permissions)}"
            )
        elif len(dangerous_permissions) > 10:  # Increased threshold
            risk_score += (len(dangerous_permissions) - 10) * 0.5  # Reduced multiplier
            risk_assessment["major_concerns"].append(
                f"High number of dangerous permissions: {len(dangerous_permissions)}"
            )
        
        # Specific critical permission concerns (reduced impact)
        critical_perms = ["READ_SMS", "ACCESS_BACKGROUND_LOCATION", "SYSTEM_ALERT_WINDOW"]
        for critical in critical_perms:
            if any(critical in perm for perm in dangerous_permissions):
                risk_score += 2  # Small penalty instead of major concern
                risk_assessment["major_concerns"].append(
                    f"Critical permission: {critical}"
                )
        
        # Determine overall risk level with much more lenient thresholds
        if risk_score >= 25:  # Reduced from 60
            risk_assessment["overall_risk"] = "critical"
        elif risk_score >= 15:  # Reduced from 35
            risk_assessment["overall_risk"] = "high"
        elif risk_score >= 8:   # Reduced from 20
            risk_assessment["overall_risk"] = "medium"
        else:
            risk_assessment["overall_risk"] = "low"
        
        risk_assessment["risk_score"] = risk_score
        
        # Identify potentially unnecessary permissions with context
        potentially_unnecessary = []
        
        # Check for permissions that are often overrequested
        common_overrequests = [
            "WRITE_EXTERNAL_STORAGE",  # Often not needed with scoped storage
            "ACCESS_COARSE_LOCATION",  # When only fine location is actually used
            "CAMERA",  # When only image picker is used
            "RECORD_AUDIO",  # When only for UI sounds
            "VIBRATE",  # Often unnecessary
            "WAKE_LOCK"  # Often overused
        ]
        
        for perm in all_permissions:
            for unnecessary in common_overrequests:
                if unnecessary in perm:
                    potentially_unnecessary.append(perm)
        
        risk_assessment["unnecessary_permissions"] = potentially_unnecessary
        
        return risk_assessment
    
    def _analyze_app_context(self, permissions):
        """Analyze app context to determine if permissions are likely legitimate"""
        context = {
            "likely_legitimate": False,
            "app_type": "unknown",
            "confidence": 0
        }
        
        # Define app types and their typical permissions
        app_types = {
            "messaging": ["READ_SMS", "SEND_SMS", "READ_CONTACTS", "INTERNET"],
            "social_media": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "INTERNET"],
            "navigation": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "INTERNET"],
            "banking": ["READ_SMS", "CAMERA", "INTERNET", "USE_FINGERPRINT"],
            "camera": ["CAMERA", "RECORD_AUDIO", "WRITE_EXTERNAL_STORAGE", "INTERNET"],
            "file_manager": ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "INTERNET"],
            "security": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "SYSTEM_ALERT_WINDOW"],
            "video_calling": ["CAMERA", "RECORD_AUDIO", "INTERNET", "ACCESS_NETWORK_STATE"]
        }
        
        # Check which app type matches best
        best_match = None
        best_score = 0
        
        for app_type, typical_perms in app_types.items():
            score = 0
            for perm in permissions:
                if any(tp in perm for tp in typical_perms):
                    score += 1
            
            if score > best_score and score >= 2:  # At least 2 matching permissions
                best_score = score
                best_match = app_type
        
        if best_match:
            context["likely_legitimate"] = True
            context["app_type"] = best_match
            context["confidence"] = min(100, (best_score / len(app_types[best_match])) * 100)
        
        return context
    
    def _generate_detailed_analysis(self, permissions):
        """Generate detailed analysis for each permission"""
        detailed_analysis = []
        
        for permission in permissions:
            perm_name = permission.split('.')[-1] if '.' in permission else permission
            
            analysis = {
                "permission": permission,
                "name": perm_name,
                "description": "",
                "risk_level": "unknown",
                "privacy_impact": "",
                "security_concern": "",
                "justification_needed": False
            }
            
            # Get risk information
            if perm_name in self.permission_risks:
                risk_info = self.permission_risks[perm_name]
                analysis["description"] = risk_info["description"]
                analysis["privacy_impact"] = risk_info["risk"]
                analysis["justification_needed"] = risk_info["justification_needed"]
            
            # Determine risk level
            for risk_level, perm_list in self.permission_categories.items():
                if any(risk_perm in perm_name for risk_perm in perm_list):
                    analysis["risk_level"] = risk_level
                    break
            
            # Security concerns based on permission type
            if "LOCATION" in perm_name:
                analysis["security_concern"] = "Location tracking and privacy invasion"
            elif "CAMERA" in perm_name or "RECORD_AUDIO" in perm_name:
                analysis["security_concern"] = "Potential surveillance and privacy violation"
            elif "SMS" in perm_name or "CALL" in perm_name:
                analysis["security_concern"] = "Access to private communications"
            elif "CONTACTS" in perm_name:
                analysis["security_concern"] = "Personal information exposure"
            elif "INTERNET" in perm_name:
                analysis["security_concern"] = "Data exfiltration and malware communication"
            elif "STORAGE" in perm_name:
                analysis["security_concern"] = "File system access and data manipulation"
            
            detailed_analysis.append(analysis)
        
        return detailed_analysis
    
    def _generate_recommendations(self, results):
        """Generate permission-related recommendations"""
        recommendations = []
        
        risk_assessment = results["risk_assessment"]
        
        # High-level recommendations based on risk
        if risk_assessment["overall_risk"] in ["high", "critical"]:
            recommendations.append({
                "priority": "High",
                "category": "Permission Reduction",
                "recommendation": "Review and minimize dangerous permissions",
                "details": "Remove unnecessary dangerous permissions and implement runtime permission requests"
            })
        
        # Specific recommendations for risky combinations
        for combo in results["permission_combinations"]:
            recommendations.append({
                "priority": "High" if combo["severity"] in ["high", "critical"] else "Medium",
                "category": "Permission Combination",
                "recommendation": f"Review {combo['name']} permission combination",
                "details": f"Risk: {combo['risk']}. Ensure proper justification and user consent."
            })
        
        # Development permission recommendations
        dev_perms = results["permission_analysis"]["development"]
        if dev_perms:
            recommendations.append({
                "priority": "High",
                "category": "Development Permissions",
                "recommendation": "Remove development permissions from production",
                "details": f"Found development permissions: {', '.join(dev_perms)}"
            })
        
        # Unnecessary permission recommendations
        if risk_assessment["unnecessary_permissions"]:
            recommendations.append({
                "priority": "Medium",
                "category": "Permission Optimization",
                "recommendation": "Review potentially unnecessary permissions",
                "details": f"Consider removing: {', '.join(risk_assessment['unnecessary_permissions'])}"
            })
        
        # Privacy-related recommendations
        high_privacy_perms = [p for p in results["detailed_analysis"] 
                             if p["justification_needed"]]
        if high_privacy_perms:
            recommendations.append({
                "priority": "Medium",
                "category": "Privacy Protection",
                "recommendation": "Implement clear permission justifications",
                "details": "Provide clear explanations for why sensitive permissions are needed"
            })
        
        # Runtime permission recommendations
        dangerous_count = len(results["dangerous_permissions"])
        if dangerous_count > 0:
            recommendations.append({
                "priority": "Medium",
                "category": "Runtime Permissions",
                "recommendation": "Implement proper runtime permission handling",
                "details": "Request permissions at runtime with clear explanations and handle denials gracefully"
            })
        
        return recommendations