// KEXY Email Warmup System - Dashboard JavaScript
// FIXED: Removes problematic API calls causing "Processing..." to hang

// Dashboard Class
class EmailWarmupDashboard {
    constructor() {
        this.apiBaseUrl = '/api';
        this.campaigns = [];
        this.currentUser = null;
        this.init();
    }

    init() {
        // REMOVED: this.loadUserSession(); - This was causing the hang
        this.bindEvents();
        this.loadCampaigns();
        this.setupProviderHandling();
        this.hideLoadingSpinner(); // Hide the processing spinner immediately
    }

    // ADDED: Hide the loading spinner
    hideLoadingSpinner() {
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    }

    // REMOVED: loadUserSession() - was calling non-existent API

    // Existing event binding (Preserved)
    bindEvents() {
        const form = document.getElementById('campaign-form');
        if (form) {
            form.addEventListener('submit', this.handleFormSubmit.bind(this));
        }
    }

    // CORRECTED: Enhanced provider handling with Amazon SES support
    setupProviderHandling() {
        this.providerConfigs = {
            // Original providers (Preserved)
            gmail: {
                host: 'smtp.gmail.com',
                port: 587,
                tls: true,
                helpText: 'For Gmail: Enable 2-Factor Authentication and generate an App Password. Use your Gmail address and the App Password (not your regular password).'
            },
            outlook: {
                host: 'smtp-mail.outlook.com',
                port: 587,
                tls: true,
                helpText: 'For Outlook/Hotmail: Enable 2-Factor Authentication and generate an App Password from your Microsoft Account security settings.'
            },
            yahoo: {
                host: 'smtp.mail.yahoo.com',
                port: 587,
                tls: true,
                helpText: 'For Yahoo Mail: Enable 2-Factor Authentication and generate an App Password for mail applications.'
            },
            custom_smtp: {
                host: '',
                port: 587,
                tls: true,
                helpText: 'Custom SMTP: Enter your SMTP server details manually. Contact your email provider for the correct settings.'
            },

            // ADDED: Amazon SES configurations
            amazon_ses_us_east_1: {
                host: 'email-smtp.us-east-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'us-east-1',
                helpText: 'Amazon SES (US East 1): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_us_west_2: {
                host: 'email-smtp.us-west-2.amazonaws.com',
                port: 587,
                tls: true,
                region: 'us-west-2',
                helpText: 'Amazon SES (US West 2): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_us_west_1: {
                host: 'email-smtp.us-west-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'us-west-1',
                helpText: 'Amazon SES (US West 1): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_eu_west_1: {
                host: 'email-smtp.eu-west-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'eu-west-1',
                helpText: 'Amazon SES (EU West 1): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_eu_central_1: {
                host: 'email-smtp.eu-central-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'eu-central-1',
                helpText: 'Amazon SES (EU Central 1): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_ap_southeast_1: {
                host: 'email-smtp.ap-southeast-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'ap-southeast-1',
                helpText: 'Amazon SES (Asia Pacific Singapore): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_ap_southeast_2: {
                host: 'email-smtp.ap-southeast-2.amazonaws.com',
                port: 587,
                tls: true,
                region: 'ap-southeast-2',
                helpText: 'Amazon SES (Asia Pacific Sydney): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_ap_northeast_1: {
                host: 'email-smtp.ap-northeast-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'ap-northeast-1',
                helpText: 'Amazon SES (Asia Pacific Tokyo): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            amazon_ses_ca_central_1: {
                host: 'email-smtp.ca-central-1.amazonaws.com',
                port: 587,
                tls: true,
                region: 'ca-central-1',
                helpText: 'Amazon SES (Canada Central): Use your IAM Access Key ID as username and Secret Access Key as password. Ensure your email/domain is verified in the SES console.'
            },
            custom_ses: {
                host: '',
                port: 587,
                tls: true,
                helpText: 'Custom Amazon SES Region: Enter your region-specific SES SMTP endpoint (e.g., email-smtp.region.amazonaws.com). Use IAM credentials for authentication.'
            }
        };
    }

    // CORRECTED: Enhanced provider change handler with SES support
    handleProviderChange(provider) {
        const config = this.providerConfigs[provider];
        const helpDiv = document.getElementById('provider-help');
        const customFields = document.getElementById('custom-smtp-fields');
        const usernameLabel = document.getElementById('username-label');
        const passwordLabel = document.getElementById('password-label');

        // Show/hide custom fields
        if (provider === 'custom_smtp' || provider === 'custom_ses') {
            if (customFields) customFields.style.display = 'block';
        } else {
            if (customFields) customFields.style.display = 'none';
        }

        // Update field labels for SES
        if (this.isAmazonSES(provider)) {
            if (usernameLabel) usernameLabel.textContent = 'IAM Access Key ID';
            if (passwordLabel) passwordLabel.textContent = 'IAM Secret Access Key';
        } else {
            if (usernameLabel) usernameLabel.textContent = 'SMTP Username';
            if (passwordLabel) passwordLabel.textContent = 'SMTP Password';
        }

        // Show provider help
        if (config && config.helpText && helpDiv) {
            helpDiv.innerHTML = `<i class="fas fa-info-circle text-blue-500 mr-2"></i>${config.helpText}`;
            helpDiv.classList.add('show');
            helpDiv.style.display = 'block';
        } else if (helpDiv) {
            helpDiv.classList.remove('show');
            helpDiv.style.display = 'none';
        }

        // Set default values
        if (config) {
            const hostField = document.getElementById('smtp-host');
            const portField = document.getElementById('smtp-port');
            const tlsField = document.getElementById('use-tls');

            if (hostField && config.host) hostField.value = config.host;
            if (portField) portField.value = config.port;
            if (tlsField) tlsField.checked = config.tls;
        }
    }

    // ADDED: Helper method to identify Amazon SES providers
    isAmazonSES(provider) {
        return provider.includes('amazon_ses') || provider === 'custom_ses';
    }

    // FIXED: Campaign loading with better error handling
    loadCampaigns() {
        fetch(`${this.apiBaseUrl}/campaigns`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (Array.isArray(data)) {
                    this.campaigns = data;
                } else if (data.campaigns && Array.isArray(data.campaigns)) {
                    this.campaigns = data.campaigns;
                } else {
                    this.campaigns = [];
                }
                this.renderCampaigns();
            })
            .catch(error => {
                console.log('No campaigns found or API not ready:', error);
                this.campaigns = [];
                this.renderCampaigns();
            });
    }

    renderCampaigns() {
        const container = document.getElementById('campaigns-container');
        if (!container) return;

        if (this.campaigns.length === 0) {
            container.innerHTML = `
                <div class="text-center py-12 text-gray-500">
                    <i class="fas fa-inbox text-4xl mb-4"></i>
                    <p class="text-lg">No campaigns yet. Create your first campaign to get started!</p>
                    <button onclick="switchTab('create')" class="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                        Create Campaign
                    </button>
                </div>
            `;
        } else {
            container.innerHTML = this.campaigns.map(campaign => this.renderCampaignCard(campaign)).join('');
        }
    }

    renderCampaignCard(campaign) {
        return `
            <div class="bg-white p-6 rounded-lg shadow-lg mb-4">
                <div class="flex justify-between items-center">
                    <div>
                        <h3 class="text-lg font-medium text-gray-900">${campaign.name}</h3>
                        <p class="text-sm text-gray-600">${campaign.email}</p>
                        <p class="text-sm text-gray-500">${campaign.provider}</p>
                    </div>
                    <div class="flex space-x-2">
                        <button onclick="dashboard.startCampaign(${campaign.id})" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                            Start
                        </button>
                        <button onclick="dashboard.deleteCampaign(${campaign.id})" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors">
                            Delete
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    // Test connection method
    async testConnection() {
        const formData = this.getFormData();
        if (!this.validateFormData(formData)) {
            return;
        }

        const submitBtn = document.querySelector('button[onclick="testConnection()"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Testing...';
        submitBtn.disabled = true;

        try {
            const response = await fetch(`${this.apiBaseUrl}/validate-smtp`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('SMTP validation successful!', 'success');
                if (this.isAmazonSES(formData.provider)) {
                    this.showNotification('Amazon SES connection verified!', 'success');
                }
            } else {
                this.showNotification(`SMTP validation failed: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Connection test failed. Please check your network connection.', 'error');
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    getFormData() {
        return {
            name: document.getElementById('campaign-name')?.value || '',
            email: document.getElementById('email-address')?.value || '',
            provider: document.getElementById('email-provider')?.value || '',
            username: document.getElementById('smtp-username')?.value || '',
            password: document.getElementById('smtp-password')?.value || '',
            smtp_host: document.getElementById('smtp-host')?.value || '',
            smtp_port: document.getElementById('smtp-port')?.value || 587,
            use_tls: document.getElementById('use-tls')?.checked || true,
            industry: document.getElementById('industry')?.value || '',
            daily_volume: document.getElementById('daily-volume')?.value || 10,
            warmup_days: document.getElementById('warmup-days')?.value || 30
        };
    }

    validateFormData(data) {
        if (!data.name || !data.email || !data.provider || !data.username || !data.password) {
            this.showNotification('Please fill in all required fields.', 'error');
            return false;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(data.email)) {
            this.showNotification('Please enter a valid email address.', 'error');
            return false;
        }

        if (this.isAmazonSES(data.provider)) {
            if (data.password.length < 20) {
                this.showNotification('Amazon SES Secret Access Key should be at least 20 characters long.', 'error');
                return false;
            }
        }

        return true;
    }

    async handleFormSubmit(event) {
        event.preventDefault();
        
        const formData = this.getFormData();
        if (!this.validateFormData(formData)) {
            return;
        }

        try {
            const response = await fetch(`${this.apiBaseUrl}/campaigns`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Campaign created successfully!', 'success');
                document.getElementById('campaign-form').reset();
                this.loadCampaigns();
                switchTab('campaigns');
            } else {
                this.showNotification(`Failed to create campaign: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Error creating campaign. Please try again.', 'error');
        }
    }

    startCampaign(campaignId) {
    fetch(`/api/campaigns/${campaignId}/start`, {  // Make sure this is the FULL path
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            this.showNotification('Campaign started successfully!', 'success');
            this.loadCampaigns();
        } else {
            this.showNotification(`Failed to start campaign: ${data.message}`, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        this.showNotification('Error starting campaign.', 'error');
    });
}
    
    deleteCampaign(campaignId) {
        if (confirm('Are you sure you want to delete this campaign?')) {
            fetch(`${this.apiBaseUrl}/campaigns/${campaignId}`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.showNotification('Campaign deleted successfully!', 'success');
                    this.loadCampaigns();
                } else {
                    this.showNotification(`Failed to delete campaign: ${data.message}`, 'error');
                }
            })
            .catch(error => {
                this.showNotification('Error deleting campaign.', 'error');
            });
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 ${this.getNotificationClasses(type)}`;
        notification.innerHTML = `
            <div class="flex items-center">
                <i class="fas ${this.getNotificationIcon(type)} mr-2"></i>
                ${message}
            </div>
        `;
        
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 5000);
    }

    getNotificationClasses(type) {
        const classes = {
            success: 'bg-green-500 text-white',
            error: 'bg-red-500 text-white',
            warning: 'bg-yellow-500 text-white',
            info: 'bg-blue-500 text-white'
        };
        return classes[type] || classes.info;
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    logout() {
        window.location.href = '/logout';
    }
}

// Global functions
function switchTab(tabName) {
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(tab => tab.classList.remove('active'));

    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));

    const selectedTab = document.getElementById(`${tabName}-tab`);
    if (selectedTab) selectedTab.classList.add('active');

    const selectedButton = document.querySelector(`[onclick="switchTab('${tabName}')"]`);
    if (selectedButton) selectedButton.classList.add('active');
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

function logout() {
    if (window.dashboard) {
        window.dashboard.logout();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new EmailWarmupDashboard();
});
