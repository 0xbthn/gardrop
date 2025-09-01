#!/usr/bin/env python3
"""
Simple Internet Reporter
Generates HTML report for internet analysis results
"""

class SimpleInternetReporter:
    def __init__(self, internet_results):
        self.results = internet_results or {}
    
    def generate_html_section(self):
        """Generate simple HTML section for internet analysis"""
        html = '<div class="section internet-analysis">'
        html += '<h2><i class="fas fa-globe"></i> Internet Artifacts Analysis</h2>'
        
        # Statistics Dashboard
        stats = self.results.get('statistics', {})
        html += '<div class="dashboard-grid">'
        
        # URLs Card
        total_urls = stats.get('total_urls', 0)
        html += f'''
        <div class="card">
            <div class="card-header">
                <div class="card-icon info">
                    <i class="fas fa-link"></i>
                </div>
                <div>
                    <div class="card-title">Total URLs</div>
                    <div class="card-value">{total_urls}</div>
                    <div class="card-description">URLs found in APK</div>
                </div>
            </div>
        </div>
        '''
        
        # Emails Card
        total_emails = stats.get('total_emails', 0)
        html += f'''
        <div class="card">
            <div class="card-header">
                <div class="card-icon warning">
                    <i class="fas fa-envelope"></i>
                </div>
                <div>
                    <div class="card-title">Email Addresses</div>
                    <div class="card-value">{total_emails}</div>
                    <div class="card-description">Email addresses found</div>
                </div>
            </div>
        </div>
        '''
        
        # Endpoints Card
        total_endpoints = stats.get('total_endpoints', 0)
        html += f'''
        <div class="card">
            <div class="card-header">
                <div class="card-icon danger">
                    <i class="fas fa-server"></i>
                </div>
                <div>
                    <div class="card-title">API Endpoints</div>
                    <div class="card-value">{total_endpoints}</div>
                    <div class="card-description">API endpoints detected</div>
                </div>
            </div>
        </div>
        '''
        
        # Hashes Card
        total_hashes = stats.get('total_hashes', 0)
        html += f'''
        <div class="card">
            <div class="card-header">
                <div class="card-icon success">
                    <i class="fas fa-hashtag"></i>
                </div>
                <div>
                    <div class="card-title">Hash Values</div>
                    <div class="card-value">{total_hashes}</div>
                    <div class="card-description">Hash values found</div>
                </div>
            </div>
        </div>
        '''
        
        html += '</div>'  # End dashboard-grid
        
        # URLs Section
        urls = self.results.get('urls', {})
        if any(urls.values()):
            html += '<h3><i class="fas fa-link"></i> URLs Found</h3>'
            html += '<div class="table-container">'
            html += '<table class="table">'
            html += '<thead><tr><th>Type</th><th>URL</th><th>Domain</th><th>File</th></tr></thead>'
            html += '<tbody>'
            
            for url_type, url_list in urls.items():
                for url_info in url_list[:10]:  # Show first 10
                    url = url_info.get('url', '')
                    domain = url_info.get('domain', '')
                    file_path = url_info.get('file', '')
                    html += f'''
                    <tr>
                        <td><span class="tag {url_type.replace("_", "-")}">{url_type.replace("_", " ").title()}</span></td>
                        <td style="word-break: break-all; max-width: 300px;">{url[:100]}{"..." if len(url) > 100 else ""}</td>
                        <td>{domain}</td>
                        <td>{file_path}</td>
                    </tr>
                    '''
            
            html += '</tbody></table></div>'
        
        # Emails Section
        emails = self.results.get('emails', [])
        if emails:
            html += '<h3><i class="fas fa-envelope"></i> Email Addresses</h3>'
            html += '<div class="table-container">'
            html += '<table class="table">'
            html += '<thead><tr><th>Email</th><th>Domain</th><th>File</th></tr></thead>'
            html += '<tbody>'
            
            for email_info in emails[:20]:  # Show first 20
                email = email_info.get('email', '')
                domain = email_info.get('domain', '')
                file_path = email_info.get('file', '')
                html += f'''
                <tr>
                    <td>{email}</td>
                    <td>{domain}</td>
                    <td>{file_path}</td>
                </tr>
                '''
            
            html += '</tbody></table></div>'
        
        # API Endpoints Section
        endpoints = self.results.get('endpoints', {})
        if any(endpoints.values()):
            html += '<h3><i class="fas fa-server"></i> API Endpoints</h3>'
            html += '<div class="table-container">'
            html += '<table class="table">'
            html += '<thead><tr><th>Type</th><th>Endpoint</th><th>Domain</th><th>File</th></tr></thead>'
            html += '<tbody>'
            
            for endpoint_type, endpoint_list in endpoints.items():
                for endpoint_info in endpoint_list[:10]:  # Show first 10
                    endpoint = endpoint_info.get('endpoint', '')
                    domain = endpoint_info.get('domain', '')
                    file_path = endpoint_info.get('file', '')
                    html += f'''
                    <tr>
                        <td><span class="tag api">{endpoint_type.replace("_", " ").title()}</span></td>
                        <td style="word-break: break-all; max-width: 300px;">{endpoint[:100]}{"..." if len(endpoint) > 100 else ""}</td>
                        <td>{domain}</td>
                        <td>{file_path}</td>
                    </tr>
                    '''
            
            html += '</tbody></table></div>'
        
        # Hashes Section
        hashes = self.results.get('hashes', {})
        if any(hashes.values()):
            html += '<h3><i class="fas fa-hashtag"></i> Hash Values</h3>'
            hash_types = ['md5_hashes', 'sha1_hashes', 'sha256_hashes']
            
            for hash_type in hash_types:
                hash_list = hashes.get(hash_type, [])
                if hash_list:
                    html += f'<h4>{hash_type.replace("_", " ").title()}</h4>'
                    html += '<div class="table-container">'
                    html += '<table class="table">'
                    html += '<thead><tr><th>Hash</th><th>File</th></tr></thead>'
                    html += '<tbody>'
                    
                    for hash_info in hash_list[:5]:  # Show first 5
                        hash_value = hash_info.get('hash', '')
                        file_path = hash_info.get('file', '')
                        html += f'''
                        <tr>
                            <td style="font-family: monospace; word-break: break-all;">{hash_value}</td>
                            <td>{file_path}</td>
                        </tr>
                        '''
                    
                    html += '</tbody></table></div>'
        
        # Network Artifacts Section
        artifacts = self.results.get('network_artifacts', {})
        if any(artifacts.values()):
            html += '<h3><i class="fas fa-network-wired"></i> Network Artifacts</h3>'
            
            # API Keys
            api_keys = artifacts.get('api_keys', [])
            if api_keys:
                html += '<h4>API Keys</h4>'
                html += '<div class="table-container">'
                html += '<table class="table">'
                html += '<thead><tr><th>Key (Masked)</th><th>File</th></tr></thead>'
                html += '<tbody>'
                
                for key_info in api_keys[:5]:  # Show first 5
                    key = key_info.get('key', '')
                    # Mask the key for security
                    masked_key = key[:4] + '*' * (len(key) - 8) + key[-4:] if len(key) > 8 else '*' * len(key)
                    file_path = key_info.get('file', '')
                    html += f'''
                    <tr>
                        <td style="font-family: monospace;">{masked_key}</td>
                        <td>{file_path}</td>
                    </tr>
                    '''
                
                html += '</tbody></table></div>'
        
        html += '</div>'  # End section
        return html
    
    def generate_summary(self):
        """Generate a summary of internet artifacts"""
        stats = self.results.get('statistics', {})
        
        summary = {
            'total_urls': stats.get('total_urls', 0),
            'total_emails': stats.get('total_emails', 0),
            'total_endpoints': stats.get('total_endpoints', 0),
            'total_hashes': stats.get('total_hashes', 0),
            'total_domains': stats.get('total_domains', 0)
        }
        
        # Risk assessment
        risk_level = 'Low'
        if summary['total_endpoints'] > 10 or summary['total_emails'] > 5:
            risk_level = 'Medium'
        if summary['total_endpoints'] > 20 or summary['total_emails'] > 10:
            risk_level = 'High'
        
        summary['risk_level'] = risk_level
        return summary 