<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fixed Dashboard JavaScript</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .code-container {
            background: #1e293b;
            border-radius: 12px;
            overflow: hidden;
        }
        .code-header {
            background: #334155;
            padding: 1rem;
            display: flex;
            justify-content: between;
            align-items: center;
        }
        .code-content {
            padding: 1.5rem;
            max-height: 70vh;
            overflow-y: auto;
        }
        .code {
            color: #e2e8f0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        .copy-btn {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .copy-btn:hover {
            background: #2563eb;
        }
        .copy-btn.copied {
            background: #10b981;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="max-w-6xl mx-auto py-8 px-4">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-gray-900 mb-2">
                <i class="fas fa-code text-blue-600 mr-3"></i>Fixed Dashboard JavaScript
            </h1>
            <p class="text-gray-600">Complete dashboard.js file with all functionality working properly</p>
        </div>

        <div class="bg-white rounded-lg shadow-lg p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4">
                <i class="fas fa-check-circle text-green-600 mr-2"></i>Fixed Issues
            </h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Added missing handleProviderChange function</span>
                </div>
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Fixed tab switching functionality</span>
                </div>
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Integrated analytics loading</span>
                </div>
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Added proper error handling</span>
                </div>
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Added SMTP validation function</span>
                </div>
                <div class="flex items-center">
                    <i class="fas fa-arrow-right text-blue-500 mr-2"></i>
                    <span>Fixed global function exposure</span>
                </div>
            </div>
        </div>

        <div class="code-container">
            <div class="code-header">
                <div class="flex items-center">
                    <i class="fas fa-file-code text-yellow-400 mr-2"></i>
                    <span class="text-white font-medium">dashboard.js</span>
                </div>
                <button id="copyBtn" class="copy-btn">
                    <i class="fas fa-copy mr-2"></i>Copy Code
                </button>
            </div>
            <div class="code-content">
                <pre class="code" id="codeContent">// Fixed Dashboard JS - Complete Version
class EmailWarmupDashboard {
    constructor() {
        this.providers = {};
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadCampaigns();
        this.loadDashboardStats();
        this.loadProviders();
    }

    bindEvents() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const tabName = e.target.textContent.toLowerCase().includes('create') ? 'create' : 
                              e.target.textContent.toLowerCase().includes('analytics') ? 'analytics' : 'campaigns';
                this.switchTab(tabName);
            });
        });

        // Form submission
        const form = document.getElementById('campaign-form');
        if (form) {
            form.addEventListener('submit', this.handleFormSubmit.bind(this));
        }

        // Provider change handler
        const providerSelect = document.getElementById('email-provider');
        if (providerSelect) {
            providerSelect.addEventListener('change', (e) => {
                this.handleProviderChange(e.target.value);
            });
        }
    }

    switchTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Remove active from all buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });

        // Show selected tab
        const selectedTab = document.getElementById(`${tabName}-tab`);
        if (selectedTab) {
            selectedTab.classList.add('active');
        }

        // Activate corresponding button
        document.querySelectorAll('.tab-button').forEach(button => {
            if ((tabName === 'create' && button.textContent.includes('Create')) ||
                (tabName === 'campaigns' && button.textContent.includes('Campaigns')) ||
                (tabName === 'analytics' && button.textContent.includes('Analytics'))) {
                button.classList.add('active');
            }
        });

        // Load analytics data when switching to analytics tab
        if (tabName === 'analytics') {
            this.loadAnalytics();
        }
    }

    handleProviderChange(provider) {
        const helpDiv = document.getElementById('provider-help');
        if (!helpDiv) return;

        if (provider && this.providers[provider]) {
            helpDiv.innerHTML = this.providers[provider].help_text;
            helpDiv.classList.add('show');

            // Update labels based on provider
            const usernameLabel = document.getElementById('username-label');
            const passwordLabel = document.getElementById('password-label');

            if (provider.includes('amazon_ses')) {
                if (usernameLabel) usernameLabel.textContent = 'Access Key ID';
                if (passwordLabel) passwordLabel.textContent = 'Secret Access Key';
            } else {
                if (usernameLabel) usernameLabel.textContent = 'SMTP Username';
                if (passwordLabel) passwordLabel.textContent = 'SMTP Password';
            }

            // Show/hide custom SMTP fields
            const customFields = document.getElementById('custom-smtp-fields');
            if (customFields) {
                customFields.style.display = provider === 'custom_smtp' ? 'block' : 'none';
            }
        } else {
            helpDiv.classList.remove('show');
        }
    }

    async loadProviders() {
        try {
            const response = await fetch('/api/providers');
            const data = await response.json();
            this.providers = data.providers || {};
        } catch (error) {
            console.error('Failed to load providers:', error);
        }
    }

    async loadDashboardStats() {
        try {
            const response = await fetch('/api/dashboard-stats');
            const data = await response.json();
            
            document.getElementById('total-campaigns').textContent = data.total_campaigns || 0;
            document.getElementById('active-campaigns').textContent = data.active_campaigns || 0;
            document.getElementById('emails-sent').textContent = data.emails_sent || 0;
            document.getElementById('success-rate').textContent = (data.success_rate || 0) + '%';
        } catch (error) {
            console.error('Failed to load dashboard stats:', error);
        }
    }

    async loadCampaigns() {
        try {
            const response = await fetch('/api/campaigns');
            const campaigns = await response.json();
            this.renderCampaigns(campaigns);
        } catch (error) {
            console.error('Failed to load campaigns:', error);
            this.renderCampaigns([]);
        }
    }

    renderCampaigns(campaigns) {
        const container = document.getElementById('campaigns-container');
        if (!container) return;

        if (campaigns.length === 0) {
            container.innerHTML = `
                <div class="text-center py-12 text-gray-500">
                    <i class="fas fa-inbox text-4xl mb-4"></i>
                    <p class="text-lg">No campaigns yet. Create your first campaign to get started!</p>
                    <button onclick="dashboard.switchTab('create')" class="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                        Create Campaign
                    </button>
                </div>
            `;
        } else {
            container.innerHTML = campaigns.map(campaign => `
                <div class="bg-white p-6 rounded-lg shadow-lg mb-4 card-hover">
                    <div class="flex justify-between items-center">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">${campaign.name}</h3>
                            <p class="text-sm text-gray-600">${campaign.email}</p>
                            <p class="text-sm text-gray-500">${campaign.provider}</p>
                            <div class="mt-2">
                                <span class="status-badge ${campaign.status === 'active' ? 'status-active' : campaign.status === 'paused' ? 'status-paused' : 'status-completed'}">
                                    ${campaign.status}
                                </span>
                            </div>
                            <div class="mt-2 text-xs text-gray-500">
                                Emails sent: ${campaign.emails_sent} | Success: ${campaign.success_rate}%
                            </div>
                        </div>
                        <div class="flex space-x-2">
                            ${campaign.status !== 'active' ? 
                                `<button onclick="dashboard.startCampaign(${campaign.id})" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                                    <i class="fas fa-play mr-1"></i>Start
                                </button>` : 
                                `<button onclick="dashboard.pauseCampaign(${campaign.id})" class="bg-yellow-600 text-white px-4 py-2 rounded-lg hover:bg-yellow-700 transition-colors">
                                    <i class="fas fa-pause mr-1"></i>Pause
                                </button>`
                            }
                            <button onclick="dashboard.viewCampaignStats(${campaign.id})" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                                <i class="fas fa-chart-line mr-1"></i>Stats
                            </button>
                            <button onclick="dashboard.deleteCampaign(${campaign.id})" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors">
                                <i class="fas fa-trash mr-1"></i>Delete
                            </button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    async handleFormSubmit(event) {
        event.preventDefault();
        
        // Show loading state
        this.showLoading(true);

        const formData = {
            name: document.getElementById('campaign-name').value,
            email: document.getElementById('email-address').value,
            provider: document.getElementById('email-provider').value,
            username: document.getElementById('smtp-username').value,
            password: document.getElementById('smtp-password').value,
            industry: document.getElementById('industry').value,
            daily_volume: parseInt(document.getElementById('daily-volume').value),
            warmup_days: parseInt(document.getElementById('warmup-days').value)
        };

        // Add custom SMTP fields if needed
        if (formData.provider === 'custom_smtp') {
            formData.smtp_host = document.getElementById('smtp-host').value;
            formData.smtp_port = parseInt(document.getElementById('smtp-port').value);
            formData.use_tls = document.getElementById('use-tls').checked;
        }

        try {
            const response = await fetch('/api/campaigns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Campaign created successfully!', 'success');
                document.getElementById('campaign-form').reset();
                this.loadCampaigns();
                this.loadDashboardStats();
                this.switchTab('campaigns');
            } else {
                this.showToast(`Failed to create campaign: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error creating campaign. Please try again.', 'error');
            console.error('Form submission error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    async startCampaign(campaignId) {
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Campaign started successfully!', 'success');
                this.loadCampaigns();
                this.loadDashboardStats();
            } else {
                this.showToast(`Failed to start campaign: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error starting campaign.', 'error');
            console.error('Start campaign error:', error);
        }
    }

    async pauseCampaign(campaignId) {
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/pause`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Campaign paused successfully!', 'success');
                this.loadCampaigns();
                this.loadDashboardStats();
            } else {
                this.showToast(`Failed to pause campaign: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error pausing campaign.', 'error');
            console.error('Pause campaign error:', error);
        }
    }

    async deleteCampaign(campaignId) {
        if (confirm('Are you sure you want to delete this campaign? This action cannot be undone.')) {
            try {
                const response = await fetch(`/api/campaigns/${campaignId}`, {
                    method: 'DELETE'
                });

                const result = await response.json();
                
                if (result.success) {
                    this.showToast('Campaign deleted successfully!', 'success');
                    this.loadCampaigns();
                    this.loadDashboardStats();
                } else {
                    this.showToast(`Failed to delete campaign: ${result.message}`, 'error');
                }
            } catch (error) {
                this.showToast('Error deleting campaign.', 'error');
                console.error('Delete campaign error:', error);
            }
        }
    }

    async viewCampaignStats(campaignId) {
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/stats`);
            const stats = await response.json();
            
            if (stats.error) {
                this.showToast('Failed to load campaign stats', 'error');
                return;
            }

            // Show stats in a modal or navigate to analytics
            this.showCampaignStatsModal(stats);
        } catch (error) {
            this.showToast('Error loading campaign stats.', 'error');
            console.error('Campaign stats error:', error);
        }
    }

    showCampaignStatsModal(stats) {
        const modal = document.getElementById('campaign-modal');
        const modalContent = document.getElementById('modal-content');
        
        if (modal && modalContent) {
            modalContent.innerHTML = `
                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700">Total Emails</h4>
                        <p class="text-2xl font-bold text-blue-600">${stats.total_emails}</p>
                    </div>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700">Success Rate</h4>
                        <p class="text-2xl font-bold text-green-600">${stats.success_rate}%</p>
                    </div>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700">Today's Emails</h4>
                        <p class="text-2xl font-bold text-purple-600">${stats.today_emails}</p>
                    </div>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700">Progress</h4>
                        <p class="text-2xl font-bold text-orange-600">${stats.progress}%</p>
                    </div>
                </div>
                <div class="mt-4">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${stats.progress}%"></div>
                    </div>
                    <p class="text-sm text-gray-600 mt-2">Campaign Progress</p>
                </div>
            `;
            modal.classList.add('show');
        }
    }

    async loadAnalytics() {
        try {
            // Get all campaigns first
            const campaignsResponse = await fetch('/api/campaigns');
            const campaigns = await campaignsResponse.json();
            
            if (campaigns.length === 0) {
                const analyticsContainer = document.querySelector('#analytics-tab');
                if (analyticsContainer) {
                    analyticsContainer.innerHTML = `
                        <div class="text-center py-12 text-gray-500">
                            <i class="fas fa-chart-line text-4xl mb-4"></i>
                            <p class="text-lg">Analytics will appear here once you have active campaigns</p>
                            <button onclick="dashboard.switchTab('create')" class="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                                Create Your First Campaign
                            </button>
                        </div>
                    `;
                }
                return;
            }

            // Load stats for the first active campaign
            const activeCampaign = campaigns.find(c => c.status === 'active') || campaigns[0];
            const statsResponse = await fetch(`/api/campaigns/${activeCampaign.id}/stats`);
            const stats = await statsResponse.json();
            
            const analyticsContainer = document.querySelector('#analytics-tab');
            if (analyticsContainer && stats && !stats.error) {
                analyticsContainer.innerHTML = `
                    <div>
                        <h2 class="text-lg font-medium text-gray-900 mb-6">
                            <i class="fas fa-chart-bar text-blue-600 mr-2"></i>Analytics Dashboard
                        </h2>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                            <div class="bg-white p-6 rounded-lg shadow card-hover">
                                <div class="flex items-center">
                                    <i class="fas fa-envelope text-blue-600 text-2xl mr-3"></i>
                                    <div>
                                        <p class="text-sm text-gray-600">Total Emails</p>
                                        <p class="text-2xl font-bold text-gray-900">${stats.total_emails}</p>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white p-6 rounded-lg shadow card-hover">
                                <div class="flex items-center">
                                    <i class="fas fa-check-circle text-green-600 text-2xl mr-3"></i>
                                    <div>
                                        <p class="text-sm text-gray-600">Success Rate</p>
                                        <p class="text-2xl font-bold text-gray-900">${stats.success_rate}%</p>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white p-6 rounded-lg shadow card-hover">
                                <div class="flex items-center">
                                    <i class="fas fa-calendar-day text-purple-600 text-2xl mr-3"></i>
                                    <div>
                                        <p class="text-sm text-gray-600">Today's Emails</p>
                                        <p class="text-2xl font-bold text-gray-900">${stats.today_emails}</p>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-white p-6 rounded-lg shadow card-hover">
                                <div class="flex items-center">
                                    <i class="fas fa-target text-orange-600 text-2xl mr-3"></i>
                                    <div>
                                        <p class="text-sm text-gray-600">Daily Target</p>
                                        <p class="text-2xl font-bold text-gray-900">${stats.daily_target}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="bg-white p-6 rounded-lg shadow">
                            <h3 class="text-lg font-medium mb-4">Campaign Progress</h3>
                            <div class="progress-bar mb-2">
                                <div class="progress-fill" style="width: ${stats.progress}%"></div>
                            </div>
                            <p class="text-sm text-gray-600">${stats.progress}% Complete</p>
                        </div>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Failed to load analytics:', error);
        }
    }

    async testConnection() {
        const provider = document.getElementById('email-provider').value;
        const username = document.getElementById('smtp-username').value;
        const password = document.getElementById('smtp-password').value;

        if (!provider || !username || !password) {
            this.showToast('Please fill in all SMTP credentials before testing', 'warning');
            return;
        }

        try {
            this.showLoading(true);
            
            const response = await fetch('/api/validate-smtp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, username, password })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('SMTP connection validated successfully!', 'success');
            } else {
                this.showToast(`SMTP validation failed: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error validating SMTP connection', 'error');
            console.error('SMTP validation error:', error);
        } finally {
            this.showLoading(false);
        }
    }

    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            if (show) {
                overlay.classList.add('show');
            } else {
                overlay.classList.remove('show');
            }
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `alert alert-${type} transform transition-all duration-300 translate-x-full`;
        toast.innerHTML = `
            <div class="flex items-center">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} mr-2"></i>
                <span>${message}</span>
            </div>
        `;

        container.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.classList.remove('translate-x-full');
        }, 100);

        // Remove after 5 seconds
        setTimeout(() => {
            toast.classList.add('translate-x-full');
            setTimeout(() => {
                if (container.contains(toast)) {
                    container.removeChild(toast);
                }
            }, 300);
        }, 5000);
    }

    closeModal() {
        const modal = document.getElementById('campaign-modal');
        if (modal) {
            modal.classList.remove('show');
        }
    }
}

// Global functions for HTML onclick handlers
function switchTab(tabName) {
    if (window.dashboard) {
        window.dashboard.switchTab(tabName);
    }
}

function handleProviderChange(provider) {
    if (window.dashboard) {
        window.dashboard.handleProviderChange(provider);
    }
}

function testConnection() {
    if (window.dashboard) {
        window.dashboard.testConnection();
    }
}

function closeModal() {
    if (window.dashboard) {
        window.dashboard.closeModal();
    }
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        // Add logout functionality here
        window.location.reload();
    }
}

// Initialize dashboard
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmailWarmupDashboard();
    window.dashboard = dashboard; // Make it globally available
});</pre>
            </div>
        </div>

        <div class="bg-blue-50 border border-blue-200 rounded-lg p-6 mt-6">
            <h3 class="text-lg font-semibold text-blue-900 mb-3">
                <i class="fas fa-lightbulb text-blue-600 mr-2"></i>How to Use
            </h3>
            <ol class="list-decimal list-inside space-y-2 text-blue-800">
                <li>Copy the JavaScript code above</li>
                <li>Save it as <code class="bg-blue-100 px-2 py-1 rounded">dashboard.js</code> in your <code class="bg-blue-100 px-2 py-1 rounded">static/js/</code> folder</li>
                <li>Make sure your HTML file includes: <code class="bg-blue-100 px-2 py-1 rounded">&lt;script src="/static/js/dashboard.js"&gt;&lt;/script&gt;</code></li>
                <li>Deploy to Railway and test the Create Campaign functionality</li>
            </ol>
        </div>
    </div>

    <script>
        document.getElementById('copyBtn').addEventListener('click', function() {
            const codeContent = document.getElementById('codeContent').textContent;
            const btn = this;
            
            navigator.clipboard.writeText(codeContent).then(function() {
                btn.innerHTML = '<i class="fas fa-check mr-2"></i>Copied!';
                btn.classList.add('copied');
                
                setTimeout(function() {
                    btn.innerHTML = '<i class="fas fa-copy mr-2"></i>Copy Code';
                    btn.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Could not copy text: ', err);
                alert('Failed to copy code. Please select and copy manually.');
            });
        });
    </script>
</body>
</html>
