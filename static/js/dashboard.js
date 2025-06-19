// Email Warmup Dashboard JavaScript - Clean Version
class EmailWarmupDashboard {
    constructor() {
        this.providers = {};
        this.campaigns = [];
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadDashboardStats();
        this.loadCampaigns();
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

        // Provider change
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

        if (tabName === 'analytics') {
            this.loadAnalytics();
        }
    }

    handleProviderChange(provider) {
        const helpDiv = document.getElementById('provider-help');
        const customFields = document.getElementById('custom-smtp-fields');
        const usernameLabel = document.getElementById('username-label');
        const passwordLabel = document.getElementById('password-label');
        
        if (!helpDiv) return;

        if (provider === 'custom_smtp') {
            if (customFields) customFields.style.display = 'block';
        } else {
            if (customFields) customFields.style.display = 'none';
        }
        
        const helpTexts = {
            'gmail': 'For Gmail: Enable 2-Factor Authentication and generate an App Password. Use your Gmail address as username.',
            'outlook': 'For Outlook: Enable 2-Factor Authentication and generate an App Password. Use your Outlook email as username.',
            'amazon_ses_us_east_1': 'Amazon SES (US East 1): Use IAM Access Key ID as username and Secret Access Key as password.',
            'amazon_ses_us_west_2': 'Amazon SES (US West 2): Use IAM Access Key ID as username and Secret Access Key as password.',
            'custom_smtp': 'Enter your custom SMTP server details. Make sure to use the correct host, port, and authentication method.'
        };
        
        if (provider && helpTexts[provider]) {
            helpDiv.innerHTML = helpTexts[provider];
            helpDiv.classList.add('show');
        } else {
            helpDiv.classList.remove('show');
        }
        
        if (provider && provider.includes('amazon_ses')) {
            if (usernameLabel) usernameLabel.textContent = 'Access Key ID';
            if (passwordLabel) passwordLabel.textContent = 'Secret Access Key';
        } else {
            if (usernameLabel) usernameLabel.textContent = 'SMTP Username';
            if (passwordLabel) passwordLabel.textContent = 'SMTP Password';
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
            this.campaigns = await response.json() || [];
            this.renderCampaigns(this.campaigns);
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
                <div class="border rounded-lg p-6 mb-4 hover:shadow-md transition-shadow">
                    <div class="flex justify-between items-start">
                        <div class="flex-1">
                            <h3 class="text-lg font-medium text-gray-900">${campaign.name || 'Untitled Campaign'}</h3>
                            <p class="text-sm text-gray-600 mt-1">${campaign.email || 'No email'}</p>
                            <div class="mt-2 flex items-center space-x-4">
                                <span class="status-badge status-${campaign.status || 'created'}">
                                    ${(campaign.status || 'created').toUpperCase()}
                                </span>
                                <span class="text-xs text-gray-500">
                                    ${campaign.provider || 'No provider'} • ${campaign.industry || 'No industry'}
                                </span>
                            </div>
                        </div>
                        <div class="flex flex-col items-end text-right">
                            <div class="text-sm text-gray-600">
                                ${campaign.emails_sent || 0} emails sent
                            </div>
                            <div class="text-sm text-gray-600">
                                ${campaign.success_rate || 0}% success rate
                            </div>
                            <div class="mt-2 flex space-x-2">
                                ${campaign.status === 'active' ? 
                                    `<button onclick="dashboard.pauseCampaign(${campaign.id})" class="text-yellow-600 hover:text-yellow-700">
                                        <i class="fas fa-pause"></i>
                                    </button>` :
                                    `<button onclick="dashboard.startCampaign(${campaign.id})" class="text-green-600 hover:text-green-700">
                                        <i class="fas fa-play"></i>
                                    </button>`
                                }
                                <button onclick="dashboard.viewCampaign(${campaign.id})" class="text-blue-600 hover:text-blue-700">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button onclick="dashboard.deleteCampaign(${campaign.id})" class="text-red-600 hover:text-red-700">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    async handleFormSubmit(event) {
        event.preventDefault();
        
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
        } finally {
            this.showLoading(false);
        }
    }

    async startCampaign(campaignId) {
        if (!confirm('Are you sure you want to start this campaign?')) return;
        
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/start`, {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Campaign started successfully!', 'success');
                this.loadCampaigns();
                this.loadDashboardStats();
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to start campaign', 'error');
        }
    }

    async pauseCampaign(campaignId) {
        if (!confirm('Are you sure you want to pause this campaign?')) return;
        
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/pause`, {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Campaign paused successfully!', 'success');
                this.loadCampaigns();
                this.loadDashboardStats();
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to pause campaign', 'error');
        }
    }

    async deleteCampaign(campaignId) {
        if (!confirm('Are you sure you want to delete this campaign? This action cannot be undone.')) return;
        
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
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to delete campaign', 'error');
        }
    }

    async viewCampaign(campaignId) {
        try {
            const response = await fetch(`/api/campaigns/${campaignId}`);
            const campaign = await response.json();
            
            const modal = document.getElementById('campaign-modal');
            const content = document.getElementById('modal-content');
            
            content.innerHTML = `
                <div class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <h4 class="font-medium text-gray-900">Campaign Name</h4>
                            <p class="text-sm text-gray-600">${campaign.name || 'N/A'}</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Email Address</h4>
                            <p class="text-sm text-gray-600">${campaign.email || 'N/A'}</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Provider</h4>
                            <p class="text-sm text-gray-600">${campaign.provider || 'N/A'}</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Status</h4>
                            <span class="status-badge status-${campaign.status || 'created'}">${(campaign.status || 'created').toUpperCase()}</span>
                        </div>
                    </div>
                </div>
            `;
            
            modal.classList.add('show');
        } catch (error) {
            this.showToast('Failed to load campaign details', 'error');
        }
    }

    async testConnection() {
        const provider = document.getElementById('email-provider').value;
        const username = document.getElementById('smtp-username').value;
        const password = document.getElementById('smtp-password').value;
        
        if (!provider || !username || !password) {
            this.showToast('Please fill in provider, username, and password first', 'warning');
            return;
        }
        
        this.showLoading(true);
        
        try {
            const response = await fetch('/api/validate-smtp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, username, password })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast('SMTP validation successful!', 'success');
            } else {
                this.showToast('SMTP validation failed: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('SMTP validation error: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async loadAnalytics() {
        try {
            const response = await fetch('/api/campaigns');
            const campaigns = await response.json();
            
            if (campaigns.length === 0) {
                const analyticsContainer = document.querySelector('#analytics-tab');
                if (analyticsContainer) {
                    analyticsContainer.innerHTML = `
                        <div class="text-center py-12 text-gray-500">
                            <i class="fas fa-chart-line text-4xl mb-4"></i>
                            <p class="text-lg">Analytics will appear here once you have active campaigns</p>
                        </div>
                    `;
                }
                return;
            }

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
                        <div class="grid grid-cols-2 gap-6">
                            <div class="bg-white p-6 rounded-lg shadow">
                                <h3 class="text-lg font-bold">Campaign Performance</h3>
                                <p>Total Emails: ${stats.total_emails}</p>
                                <p>Success Rate: ${stats.success_rate}%</p>
                                <p>Today's Emails: ${stats.today_emails}</p>
                            </div>
                            <div class="bg-white p-6 rounded-lg shadow">
                                <h3 class="text-lg font-bold">Progress</h3>
                                <p>Campaign Progress: ${stats.progress}%</p>
                                <p>Daily Target: ${stats.daily_target}</p>
                            </div>
                        </div>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Failed to load analytics:', error);
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

    showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'exclamation'} mr-2"></i>
            ${message}
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        
        setTimeout(() => {
            toast.classList.remove('show');
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
        window.location.reload();
    }
}

// Initialize dashboard
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmailWarmupDashboard();
    window.dashboard = dashboard;
});
