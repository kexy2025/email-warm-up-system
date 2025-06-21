// Email Warmup Dashboard JavaScript - Enhanced Version with Recipients Management
class EmailWarmupDashboard {
    constructor() {
        this.providers = {};
        this.campaigns = [];
        this.recipients = [];
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadDashboardStats();
        this.loadCampaigns();
        this.loadProviders();
        this.loadRecipients();
        this.initializeUserMenu();
    }

    // Enhanced user menu initialization
    initializeUserMenu() {
        const userMenuButton = document.getElementById('user-menu-button');
        const userMenu = document.getElementById('user-menu');
        
        if (userMenuButton && userMenu) {
            // Toggle menu on button click
            userMenuButton.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                userMenu.classList.toggle('hidden');
            });

            // Close menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!userMenuButton.contains(e.target) && !userMenu.contains(e.target)) {
                    userMenu.classList.add('hidden');
                }
            });

            // Handle menu item clicks
            const menuItems = userMenu.querySelectorAll('a');
            menuItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    const href = item.getAttribute('href');
                    const onclick = item.getAttribute('onclick');
                    
                    // Let base.html handle logout - no interference
                    if (href && href !== '#') {
                        userMenu.classList.add('hidden');
                        // Let the browser handle the navigation
                    }
                });
            });
        }
    }

    bindEvents() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const tabName = e.target.textContent.toLowerCase().includes('create') ? 'create' : 
                              e.target.textContent.toLowerCase().includes('analytics') ? 'analytics' : 
                              e.target.textContent.toLowerCase().includes('recipients') ? 'recipients' : 'campaigns';
                this.switchTab(tabName);
            });
        });

        // Form submission
        const form = document.getElementById('campaign-form');
        if (form) {
            form.addEventListener('submit', this.handleFormSubmit.bind(this));
        }

        // Recipients form
        const recipientsForm = document.getElementById('recipients-form');
        if (recipientsForm) {
            recipientsForm.addEventListener('submit', this.handleRecipientsSubmit.bind(this));
        }

        // Provider change
        const providerSelect = document.getElementById('email-provider');
        if (providerSelect) {
            providerSelect.addEventListener('change', (e) => {
                this.handleProviderChange(e.target.value);
            });
        }

        // Global refresh button
        const refreshBtn = document.querySelector('[onclick="refreshDashboard()"]');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.refreshDashboard();
            });
        }

        // Recipients management buttons
        this.bindRecipientEvents();
    }

    bindRecipientEvents() {
        // Bulk import button
        const bulkImportBtn = document.getElementById('bulk-import-btn');
        if (bulkImportBtn) {
            bulkImportBtn.addEventListener('click', () => this.showBulkImportModal());
        }

        // File upload handler
        const fileInput = document.getElementById('csv-file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
        }
    }

    // Enhanced refresh functionality
    refreshDashboard() {
        this.showToast('Refreshing dashboard...', 'info');
        
        // Reload all data
        Promise.all([
            this.loadDashboardStats(),
            this.loadCampaigns(),
            this.loadProviders(),
            this.loadRecipients()
        ]).then(() => {
            this.showToast('Dashboard refreshed successfully!', 'success');
        }).catch(error => {
            console.error('Refresh error:', error);
            this.showToast('Refresh completed with some errors', 'warning');
        });
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
                (tabName === 'analytics' && button.textContent.includes('Analytics')) ||
                (tabName === 'recipients' && button.textContent.includes('Recipients'))) {
                button.classList.add('active');
            }
        });

        if (tabName === 'analytics') {
            this.loadAnalytics();
        } else if (tabName === 'recipients') {
            this.loadRecipients();
        }
    }

    // ===========================================
    // RECIPIENTS MANAGEMENT FUNCTIONALITY - FIXED FOR API RESPONSE STRUCTURE
    // ===========================================

    async loadRecipients() {
        try {
            const response = await fetch('/api/recipients');
            if (!response.ok) {
                console.warn('Recipients API not available:', response.status);
                this.recipients = [];
                this.renderRecipients([]);
                this.updateRecipientStats({ total_count: 0, active_count: 0 });
                return;
            }
            
            // ✅ FIXED: Handle the correct API response structure
            const data = await response.json();
            
            // The API returns: { recipients: [...], total_count: X, active_count: Y, categories: [...] }
            // We need to access data.recipients, not just data
            this.recipients = data.recipients || [];
            this.renderRecipients(this.recipients);
            this.updateRecipientStats(data);
            
            // Update category dropdown if it exists
            this.updateCategoryFilter(data.categories || []);
            
        } catch (error) {
            console.warn('Recipients functionality not available:', error);
            this.recipients = [];
            this.renderRecipients([]);
            this.updateRecipientStats({ total_count: 0, active_count: 0 });
        }
    }

    updateCategoryFilter(categories) {
        const categoryFilter = document.getElementById('category-filter');
        if (categoryFilter && categories.length > 0) {
            // Clear existing options except "All Categories"
            const allOption = categoryFilter.querySelector('option[value=""]');
            categoryFilter.innerHTML = '';
            if (allOption) categoryFilter.appendChild(allOption);
            
            // Add dynamic categories
            categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categoryFilter.appendChild(option);
            });
        }
    }

    renderRecipients(recipients) {
        const container = document.getElementById('recipients-list');
        if (!container) return;

        if (recipients.length === 0) {
            container.innerHTML = `
                <div class="text-center py-12 text-gray-500">
                    <i class="fas fa-users text-4xl mb-4"></i>
                    <p class="text-lg">No recipients yet. Add recipients to expand your email reach!</p>
                    <button onclick="dashboard.showAddRecipientModal()" class="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                        Add Recipients
                    </button>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="space-y-4">
                    ${recipients.map(recipient => `
                        <div class="border rounded-lg p-4 hover:shadow-md transition-shadow">
                            <div class="flex justify-between items-start">
                                <div class="flex-1">
                                    <h4 class="font-medium text-gray-900">${recipient.name || 'Unknown'}</h4>
                                    <p class="text-sm text-gray-600">${recipient.email}</p>
                                    <div class="mt-2 flex items-center space-x-4">
                                        <span class="status-badge status-${recipient.status || 'active'}">
                                            ${(recipient.status || 'active').toUpperCase()}
                                        </span>
                                        <span class="text-xs text-gray-500">
                                            ${recipient.category || 'General'} • Added ${new Date(recipient.created_at).toLocaleDateString()}
                                        </span>
                                    </div>
                                </div>
                                <div class="flex space-x-2">
                                    <button onclick="dashboard.editRecipient(${recipient.id})" class="text-blue-600 hover:text-blue-700" title="Edit">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button onclick="dashboard.toggleRecipientStatus(${recipient.id})" class="text-yellow-600 hover:text-yellow-700" title="Toggle Status">
                                        <i class="fas fa-${recipient.status === 'active' ? 'pause' : 'play'}"></i>
                                    </button>
                                    <button onclick="dashboard.deleteRecipient(${recipient.id})" class="text-red-600 hover:text-red-700" title="Delete">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }
    }

    // ✅ FIXED: Handle the API response structure correctly
    updateRecipientStats(data) {
        // data contains: { total_count: X, active_count: Y, ... }
        const totalRecipients = data.total_count || 0;
        const activeRecipients = data.active_count || 0;
        
        // Update stats in recipients tab
        this.updateElement('total-recipients', totalRecipients);
        this.updateElement('active-recipients', activeRecipients);
        this.updateElement('recently-emailed', 0); // You can add this to API later
        this.updateElement('avg-success-rate', '0%'); // You can add this to API later
    }

    async handleRecipientsSubmit(event) {
        event.preventDefault();
        
        this.showLoading(true);
        
        const formData = {
            name: document.getElementById('recipient-name').value,
            email: document.getElementById('recipient-email').value,
            category: document.getElementById('recipient-category').value,
            status: document.getElementById('recipient-status').value || 'active'
        };

        try {
            const response = await fetch('/api/recipients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient added successfully!', 'success');
                document.getElementById('recipients-form').reset();
                this.loadRecipients();
                this.closeModal();
            } else {
                this.showToast(`Failed to add recipient: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error adding recipient. Please try again.', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    showAddRecipientModal() {
        // Create modal if it doesn't exist
        let modal = document.getElementById('add-recipient-modal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }
    }

    async submitRecipientModal() {
        this.showLoading(true);
        
        const formData = {
            name: document.getElementById('recipient-name').value,
            email: document.getElementById('recipient-email').value,
            category: document.getElementById('recipient-category').value,
            status: document.getElementById('recipient-status').value || 'active'
        };

        try {
            const response = await fetch('/api/recipients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient added successfully!', 'success');
                this.loadRecipients();
                this.closeModal();
                // Clear form
                document.getElementById('add-recipient-form').reset();
            } else {
                this.showToast(`Failed to add recipient: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error adding recipient. Please try again.', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    showBulkImportModal() {
        const modal = document.getElementById('bulk-import-modal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }
    }

    async handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (file.type !== 'text/csv' && !file.name.endsWith('.csv')) {
            this.showToast('Please select a valid CSV file', 'error');
            return;
        }

        this.showLoading(true);

        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/api/recipients/bulk-import', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast(`Successfully imported ${result.imported_count} recipients!`, 'success');
                this.loadRecipients();
                this.closeModal();
            } else {
                this.showToast(`Import failed: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error importing recipients. Please try again.', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async deleteRecipient(recipientId) {
        if (!confirm('Are you sure you want to delete this recipient?')) return;
        
        try {
            const response = await fetch(`/api/recipients/${recipientId}`, {
                method: 'DELETE'
            });
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient deleted successfully!', 'success');
                this.loadRecipients();
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to delete recipient', 'error');
        }
    }

    async toggleRecipientStatus(recipientId) {
        try {
            const response = await fetch(`/api/recipients/${recipientId}/toggle-status`, {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.success) {
                this.showToast(`Recipient status updated!`, 'success');
                this.loadRecipients();
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to update recipient status', 'error');
        }
    }

    async editRecipient(recipientId) {
        try {
            const response = await fetch(`/api/recipients/${recipientId}`);
            const recipient = await response.json();
            
            // Show edit modal (similar to add modal but with pre-filled data)
            this.showEditRecipientModal(recipient);
        } catch (error) {
            this.showToast('Failed to load recipient details', 'error');
        }
    }

    // ===========================================
    // EXISTING FUNCTIONALITY (UNCHANGED)
    // ===========================================

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
            this.providers = data || {};
        } catch (error) {
            console.error('Failed to load providers:', error);
        }
    }

    async loadDashboardStats() {
        try {
            const response = await fetch('/api/dashboard-stats');
            const data = await response.json();
            
            // Update stats with fallback values
            this.updateElement('total-campaigns', data.total_campaigns || 0);
            this.updateElement('active-campaigns', data.active_campaigns || 0);
            this.updateElement('emails-sent', data.emails_sent || 0);
            this.updateElement('success-rate', (data.success_rate || 0).toFixed(1) + '%');
            
        } catch (error) {
            console.error('Failed to load dashboard stats:', error);
            // Set default values on error
            this.updateElement('total-campaigns', 0);
            this.updateElement('active-campaigns', 0);
            this.updateElement('emails-sent', 0);
            this.updateElement('success-rate', '0.0%');
        }
    }

    // Helper method to safely update elements
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
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
                            <div class="mt-2">
                                <span class="text-xs text-blue-600">
                                    <i class="fas fa-users mr-1"></i>
                                    ${campaign.recipient_count || 0} recipients assigned
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
                                    `<button onclick="dashboard.pauseCampaign(${campaign.id})" class="text-yellow-600 hover:text-yellow-700" title="Pause">
                                        <i class="fas fa-pause"></i>
                                    </button>` :
                                    `<button onclick="dashboard.startCampaign(${campaign.id})" class="text-green-600 hover:text-green-700" title="Start">
                                        <i class="fas fa-play"></i>
                                    </button>`
                                }
                                <button onclick="dashboard.viewCampaign(${campaign.id})" class="text-blue-600 hover:text-blue-700" title="View">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button onclick="dashboard.deleteCampaign(${campaign.id})" class="text-red-600 hover:text-red-700" title="Delete">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    // Rest of existing campaign functionality...
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
            
            this.showToast(`Campaign: ${campaign.name} - Status: ${campaign.status}`, 'info');
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
            
            const analyticsContainer = document.querySelector('#analytics-tab');
            if (!analyticsContainer) return;
            
            if (campaigns.length === 0) {
                analyticsContainer.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <i class="fas fa-chart-line text-4xl mb-4"></i>
                        <p class="text-lg">Analytics will appear here once you have active campaigns</p>
                    </div>
                `;
                return;
            }

            const activeCampaign = campaigns.find(c => c.status === 'active') || campaigns[0];
            const statsResponse = await fetch(`/api/campaigns/${activeCampaign.id}/stats`);
            const stats = await statsResponse.json();
            
            if (stats && !stats.error) {
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
                                <p>Total Recipients: ${stats.total_recipients || 0}</p>
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
        let overlay = document.getElementById('loading-overlay');
        if (show && !overlay) {
            overlay = document.createElement('div');
            overlay.id = 'loading-overlay';
            overlay.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            overlay.innerHTML = `
                <div class="bg-white rounded-lg p-6 flex items-center space-x-3">
                    <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                    <span class="text-gray-700">Loading...</span>
                </div>
            `;
            document.body.appendChild(overlay);
        }
        
        if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
            if (!show) {
                setTimeout(() => {
                    if (overlay && overlay.parentNode) {
                        overlay.parentNode.removeChild(overlay);
                    }
                }, 300);
            }
        }
    }

    showToast(message, type = 'success') {
        // Create toast container if it doesn't exist
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'fixed top-4 right-4 z-50 space-y-2';
            document.body.appendChild(container);
        }
        
        const toast = document.createElement('div');
        toast.className = `toast px-4 py-3 rounded-lg shadow-lg max-w-sm transition-all duration-300 transform translate-x-full opacity-0`;
        
        // Set colors based on type
        const colors = {
            success: 'bg-green-500 text-white',
            error: 'bg-red-500 text-white',
            warning: 'bg-yellow-500 text-white',
            info: 'bg-blue-500 text-white'
        };
        
        const icons = {
            success: 'check-circle',
            error: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        
        toast.className += ` ${colors[type] || colors.info}`;
        toast.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="flex items-center">
                    <i class="fas fa-${icons[type] || icons.info} mr-2"></i>
                    <span>${message}</span>
                </div>
                <button type="button" class="ml-4 text-white hover:text-gray-200" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        container.appendChild(toast);
        
        // Animate in
        setTimeout(() => {
            toast.classList.remove('translate-x-full', 'opacity-0');
        }, 100);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            toast.classList.add('translate-x-full', 'opacity-0');
            setTimeout(() => {
                if (container.contains(toast)) {
                    container.removeChild(toast);
                }
            }, 300);
        }, 5000);
    }

    closeModal() {
        // Close all possible modals
        const modals = [
            'add-recipient-modal',
            'bulk-import-modal',
            'campaign-modal',
            'recipient-modal', 
            'campaign-recipients-modal'
        ];
        
        modals.forEach(modalId => {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                modal.style.display = 'none';
            }
        });
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

function refreshDashboard() {
    if (window.dashboard) {
        window.dashboard.refreshDashboard();
    }
}

// Initialize dashboard - FIXED VERSION (no logout conflicts)
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmailWarmupDashboard();
    window.dashboard = dashboard;
    
    console.log('Dashboard initialized successfully with Recipients Management functionality');
    
    // ✅ FIXED: Bind add recipient form submission to the existing modal
    const addRecipientForm = document.getElementById('add-recipient-form');
    if (addRecipientForm) {
        addRecipientForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await dashboard.submitRecipientModal();
        });
    }
    
    // ✅ FIXED: Bind bulk import form submission
    const bulkImportForm = document.getElementById('bulk-import-form');
    if (bulkImportForm) {
        bulkImportForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('csv-file-input');
            if (fileInput.files.length > 0) {
                await dashboard.handleFileUpload({ target: fileInput });
            }
        });
    }
});
