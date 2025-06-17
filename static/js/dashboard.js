// KEXY Email Warmup System - Dashboard JavaScript
// CORRECTED: Preserves all existing functionality + adds Amazon SES support

// Existing Dashboard Class (Preserved)
class EmailWarmupDashboard {
    constructor() {
        this.apiBaseUrl = '/api';
        this.campaigns = [];
        this.currentUser = null;
        this.init();
    }

    init() {
        this.loadUserSession();
        this.bindEvents();
        this.loadCampaigns();
        this.setupProviderHandling();
    }

    // Existing authentication methods (Preserved)
    loadUserSession() {
        // Keep existing session management
        fetch('/api/user/session')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.currentUser = data.user;
                    this.updateUserInterface();
                }
            })
            .catch(error => console.error('Session load error:', error));
    }

    updateUserInterface() {
        if (this.currentUser) {
            document.getElementById('user-welcome').textContent = 
                `Welcome back, ${this.currentUser.username}! (Persistent login active)`;
        }
    }

    // Existing event binding (Preserved)
    bindEvents() {
        const form = document.getElementById('campaign-form');
        if (form) {
            form.addEventListener('submit', this.handleFormSubmit.bind(this));
        }

        // Keep all existing event listeners
        this.bindExistingEvents();
    }

    bindExistingEvents() {
        // Preserve all existing event bindings
        // Modal controls
        document.addEventListener('click', (e) => {
            if (e.target.matches('[onclick*="openCampaignModal"]')) {
                this.openCampaignModal();
            }
        });
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
            customFields.style.display = 'block';
        } else {
            customFields.style.display = 'none';
        }

        // Update field labels for SES
        if (this.isAmazonSES(provider)) {
            usernameLabel.textContent = 'IAM Access Key ID';
            passwordLabel.textContent = 'IAM Secret Access Key';
        } else {
            usernameLabel.textContent = 'SMTP Username';
            passwordLabel.textContent = 'SMTP Password';
        }

        // Show provider help
        if (config && config.helpText) {
            helpDiv.innerHTML = `${config.helpText}`;
            helpDiv.classList.remove('hidden');
        } else {
            helpDiv.classList.add('hidden');
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

    // Existing campaign management methods (Preserved)
    loadCampaigns() {
        fetch(`${this.apiBaseUrl}/campaigns`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.campaigns = data.campaigns;
                    this.renderCampaigns();
                }
            })
            .catch(error => console.error('Error loading campaigns:', error));
    }

    renderCampaigns() {
        const container = document.getElementById('campaigns-container');
        if (this.campaigns.length === 0) {
            container.innerHTML = `
                
                    
                    No campaigns yet. Create your first campaign to get started!
                
            `;
        } else {
            // Render existing campaigns
            container.innerHTML = this.campaigns.map(campaign => this.renderCampaignCard(campaign)).join('');
        }
    }

    renderCampaignCard(campaign) {
        return `
            
                
                    
                        ${campaign.name}
                        ${campaign.email}
                        ${campaign.provider}
                    
                    
                        
                            Start
                        
                        
                            Delete
                        
                    
                
            
        `;
    }

    // CORRECTED: Enhanced SMTP validation with SES support
    async testConnection() {
        const formData = this.getFormData();
        if (!this.validateFormData(formData)) {
            return;
        }

        const submitBtn = document.querySelector('button[onclick="testConnection()"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = 'Testing...';
        submitBtn.disabled = true;

        try {
            const response = await fetch(`${this.apiBaseUrl}/validate-smtp`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('SMTP validation successful!', 'success');
                
                // Special success message for SES
                if (this.isAmazonSES(formData.provider)) {
                    this.showNotification('Amazon SES connection verified! Your IAM credentials are working correctly.', 'success');
                }
            } else {
                this.showNotification(`SMTP validation failed: ${result.message}`, 'error');
                
                // Provide SES-specific error guidance
                if (this.isAmazonSES(formData.provider)) {
                    this.showSESErrorGuidance(result.message);
                }
            }
        } catch (error) {
            this.showNotification('Connection test failed. Please check your network connection.', 'error');
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    // ADDED: SES-specific error guidance
    showSESErrorGuidance(errorMessage) {
        let guidance = '';
        
        if (errorMessage.includes('authentication') || errorMessage.includes('credential')) {
            guidance = 'SES Authentication Error: Verify your IAM Access Key ID and Secret Access Key. Ensure the IAM user has SES sending permissions.';
        } else if (errorMessage.includes('verification') || errorMessage.includes('verified')) {
            guidance = 'SES Verification Error: Ensure your email address or domain is verified in the SES console for your selected region.';
        } else if (errorMessage.includes('sandbox')) {
            guidance = 'SES Sandbox Mode: Your account may be in sandbox mode. Request production access in the SES console to send to unverified addresses.';
        } else {
            guidance = 'SES Error: Check your AWS SES console for sending limits, account status, and regional availability.';
        }
        
        this.showNotification(guidance, 'warning');
    }

    // Existing form handling methods (Preserved)
    getFormData() {
        return {
            name: document.getElementById('campaign-name').value,
            email: document.getElementById('email-address').value,
            provider: document.getElementById('email-provider').value,
            username: document.getElementById('smtp-username').value,
            password: document.getElementById('smtp-password').value,
            smtp_host: document.getElementById('smtp-host')?.value || '',
            smtp_port: document.getElementById('smtp-port')?.value || 587,
            use_tls: document.getElementById('use-tls')?.checked || true
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

        // ADDED: SES-specific validation
        if (this.isAmazonSES(data.provider)) {
            return this.validateSESData(data);
        }

        return true;
    }

    // ADDED: SES-specific validation
    validateSESData(data) {
        if (data.password.length < 20) {
            this.showNotification('Amazon SES Secret Access Key should be at least 20 characters long.', 'error');
            return false;
        }

        if (data.provider === 'custom_ses' && !data.smtp_host.includes('amazonaws.com')) {
            this.showNotification('Custom SES host should be an AWS SES endpoint (*.amazonaws.com).', 'warning');
        }

        return true;
    }

    // Existing form submission (Preserved)
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
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Campaign created successfully!', 'success');
                this.closeCampaignModal();
                this.loadCampaigns();
            } else {
                this.showNotification(`Failed to create campaign: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Error creating campaign. Please try again.', 'error');
        }
    }

    // Existing utility methods (Preserved)
    openCampaignModal() {
        document.getElementById('campaign-modal').classList.remove('hidden');
    }

    closeCampaignModal() {
        document.getElementById('campaign-modal').classList.add('hidden');
        document.getElementById('campaign-form').reset();
        document.getElementById('provider-help').classList.add('hidden');
        document.getElementById('custom-smtp-fields').style.display = 'none';
    }

    startCampaign(campaignId) {
        fetch(`${this.apiBaseUrl}/campaigns/${campaignId}/start`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.getCSRFToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.showNotification('Campaign started successfully!', 'success');
                this.loadCampaigns();
            } else {
                this.showNotification(`Failed to start campaign: ${data.message}`, 'error');
            }
        });
    }

    deleteCampaign(campaignId) {
        if (confirm('Are you sure you want to delete this campaign?')) {
            fetch(`${this.apiBaseUrl}/campaigns/${campaignId}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': this.getCSRFToken()
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.showNotification('Campaign deleted successfully!', 'success');
                    this.loadCampaigns();
                } else {
                    this.showNotification(`Failed to delete campaign: ${data.message}`, 'error');
                }
            });
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 ${this.getNotificationClasses(type)}`;
        notification.innerHTML = `
            
                
                ${message}
            
        `;
        
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
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

    getCSRFToken() {
        const token = document.querySelector('meta[name="csrf-token"]');
        return token ? token.getAttribute('content') : '';
    }

    logout() {
        fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.getCSRFToken()
            }
        })
        .then(() => {
            window.location.href = '/login';
        });
    }
}

// Global functions (Preserved)
function openCampaignModal() {
    if (window.dashboard) {
        window.dashboard.openCampaignModal();
    }
}

function closeCampaignModal() {
    if (window.dashboard) {
        window.dashboard.closeCampaignModal();
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

function logout() {
    if (window.dashboard) {
        window.dashboard.logout();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new EmailWarmupDashboard();
});
