# Gardrop

![Gardrop Banner](gardroployd.png)



A comprehensive, feature-rich static security analysis tool for Android APK, XAPK, and AAB files. This tool provides deep security analysis, compliance checking, and detailed reporting capabilities.

## Features

### **Core Analysis**
- **APK Structure Analysis** - Complete file structure and integrity analysis
- **AndroidManifest.xml Analysis** - Deep manifest inspection and security assessment
- **DEX Code Analysis** - Bytecode analysis and vulnerability detection
- **Native Library Analysis** - Binary analysis for native code vulnerabilities
- **Assets & Resources Analysis** - Resource file security assessment
- **Hardcoded Secrets Detection** - Advanced pattern matching for sensitive data

### **Advanced Security Modules**
- **Certificate & Signing Analysis** - Certificate validation and signing scheme verification
- **Network Security Analysis** - Network configuration and communication security
- **Code Quality Analysis** - Complexity metrics, code smells, and quality assessment
- **Permissions Analysis** - Comprehensive permission usage and risk assessment

### **Reporting & Visualization**
- **Interactive HTML Dashboard** - Beautiful, interactive reports with charts
- **Executive Summary** - High-level security assessment for stakeholders
- **Technical Reports** - Detailed technical analysis for developers
- **Compliance Reports** - OWASP, GDPR, PCI DSS compliance checking
- **Comparison Reports** - Compare multiple analysis results
- **Multiple Export Formats** - JSON, CSV, HTML export options

### **Advanced Features**
- **Configurable Analysis** - Customizable analysis settings via JSON config
- **Quick Mode** - Fast analysis for initial assessment
- **Module Selection** - Run specific analysis modules only
- **Threading Support** - Multi-threaded analysis for better performance
- **Compliance Checking** - Built-in compliance standards validation
- **Vulnerability Database** - Structured vulnerability tracking

## Installation

### Prerequisites
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3 python3-pip binutils file

# Install Android SDK tools (optional but recommended)
# Download from: https://developer.android.com/studio
# Add to PATH: ~/Android/Sdk/tools and ~/Android/Sdk/platform-tools

sudo apt-get install apktool dex2jar
```

### Tool Installation
```bash
# Clone the repository
git clone https://github.com/0xbthn/gardrop.git
cd gardrop

# Install Python dependencies (none required - uses standard library)
# pip install -r requirements.txt
# Read requirements.txt

# Make executable
chmod +x apk_analyzer.py
```

## 📖 Usage

### Basic Usage
```bash
# Analyze an APK file
python3 apk_analyzer.py app.apk

# Analyze XAPK file
python3 apk_analyzer.py app.xapk

# Custom output directory
python3 apk_analyzer.py app.apk -o detailed_report
```

### Advanced Usage
```bash
# Quick analysis with verbose output
python3 apk_analyzer.py app.apk --verbose --quick

# Compare with previous analysis
python3 apk_analyzer.py app.apk --compare previous_analysis.json

# Export results to CSV
python3 apk_analyzer.py app.apk --export csv

# Check specific compliance standards
python3 apk_analyzer.py app.apk --compliance gdpr,owasp

# Use custom configuration
python3 apk_analyzer.py app.apk --config my_config.json

# Run only specific modules
python3 apk_analyzer.py app.apk --only-modules security,network

# Skip specific modules
python3 apk_analyzer.py app.apk --skip-modules code_quality
```

### Configuration
Create a `config.json` file to customize analysis settings:

```json
{
  "analysis": {
    "quick_mode": false,
    "threads": 4,
    "timeout": 300
  },
  "security": {
    "enable_advanced_checks": true,
    "check_obfuscation": true
  },
  "network": {
    "check_cleartext": true,
    "check_certificate_pinning": true
  }
}
```

## 📊 Output

The tool generates comprehensive reports in the output directory:

### 📁 **Generated Files**
- `security_report.html` - Basic HTML report

### 📈 **Dashboard Features**
- **Security Score Visualization** - Overall security assessment
- **Vulnerability Distribution** - Charts showing vulnerability types
- **Permission Analysis** - Permission usage and risk assessment
- **Compliance Status** - Real-time compliance checking
- **Interactive Filters** - Filter vulnerabilities by severity/category

## 🔧 Analysis Modules

### 1. **APK Structure Analyzer**
- File integrity validation
- ZIP structure analysis
- Content enumeration
- Size and compression analysis

### 2. **Manifest Analyzer**
- Component security assessment
- Intent filter analysis
- Permission usage analysis
- Security configuration review

### 3. **DEX Analyzer**
- Bytecode analysis
- Method and class inspection
- String extraction
- API usage analysis

### 4. **Security Checker**
- Obfuscation detection
- Debug settings analysis
- Backup configuration review
- Anti-tampering assessment

### 5. **Certificate Analyzer**
- Certificate validation
- Signing scheme verification
- Expiration checking
- Algorithm strength assessment

### 6. **Network Analyzer**
- Network security configuration
- Cleartext traffic detection
- Certificate pinning analysis
- Domain verification checking

### 7. **Code Quality Analyzer**
- Cyclomatic complexity analysis
- Code duplication detection
- Dead code identification
- Naming convention checking

### 8. **Secrets Detector**
- Hardcoded credentials detection
- API key identification
- Token extraction
- Sensitive data discovery

## 🛡️ Security Features

### **Vulnerability Detection**
- SQL injection patterns
- Weak encryption algorithms
- Insecure communication
- Improper data storage
- Code injection vulnerabilities
- Privilege escalation risks

### **Compliance Standards**
- **OWASP Mobile Top 10** - Mobile security best practices
- **GDPR** - Data protection compliance
- **PCI DSS** - Payment card security
- **ISO 27001** - Information security management

### **Risk Assessment**
- Severity-based vulnerability scoring
- Impact analysis for each finding
- Remediation recommendations
- Security score calculation

## 📋 Supported File Formats

- **APK** - Android Application Package
- **XAPK** - Extended APK (with OBB files)
- **AAB** - Android App Bundle (basic support)

## 🔍 Example Output

```
🔒 Advanced APK Security Analysis Tool
                                ________                 .___                      ____   ________ 
                                /  _____/_____ _______  __| _/______  ____ ______   \   \ /   /_   |
                                /   \  ___\__  \\_  __ \/ __ |\_  __ \/  _ \\____ \   \   Y   / |   |
                                \    \_\  \/ __ \|  | \/ /_/ | |  | \(  <_> )  |_> >   \     /  |   |
                                \______  (____  /__|  \____ | |__|   \____/|   __/     \___/   |___|
                                        \/     \/           \/              |__|                     
                                                        (0xbthn)

[1/13] 📁 APK Structure Analysis
────────────────────────────────────────────────────────
[SUCCESS] Step completed successfully!

[2/13] 📋 AndroidManifest.xml Analysis
────────────────────────────────────────────────────────
[SUCCESS] Step completed successfully!

[3/13] 🔍 DEX Code Analysis
────────────────────────────────────────────────────────
[SUCCESS] Step completed successfully!

...

╔══════════════════════════════════════════════════════════════╗
║                        ANALYSIS COMPLETE                        ║
╚══════════════════════════════════════════════════════════════╝

Security Score: 75/100
Results Location: /path/to/analysis_output_2025-09-01_00-00-00
Generated Reports:
   • security_analysis.json - Detailed technical report
   • security_report.html - Visual HTML dashboard
   • security_summary.txt - Executive summary
   • interactive_dashboard.html - Interactive dashboard
   • compliance_report.html - Compliance assessment

Analysis completed successfully!
```
### Development Setup
```bash
# Clone the repository
git clone https://github.com/0xbthn/gardrop.git
cd gardrop

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP Mobile Security Project** - For security guidelines and best practices
- **Android Security Team** - For platform security insights
- **Open Source Community** - For various tools and libraries used

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/mobile-tools/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/mobile-tools/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/mobile-tools/wiki)

## 🔄 Version History

### v2.0.0 (Current)
- ✨ Interactive HTML dashboard with Chart.js
- 🔒 Advanced certificate and signing analysis
- 🌐 Comprehensive network security analysis
- 📊 Code quality and complexity analysis
- 📋 Compliance checking (OWASP, GDPR, PCI DSS)
- 🔄 Comparison and trending analysis
- ⚙️ Configurable analysis settings
- 📤 Multiple export formats (JSON, CSV, HTML)

### v1.0.0
- 🔍 Basic APK structure analysis
- 📋 Manifest analysis
- 🛡️ Security vulnerability detection
- 📄 Basic HTML and JSON reporting

---

**Made with ❤️ for the security community**
**Currently repo is being developed. You can throw PR for your mistakes and ideas you encounter**