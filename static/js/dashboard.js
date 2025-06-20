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
                    
                    // Handle logout specially
                    if (onclick && onclick.includes('handleLogout')) {
                        e.preventDefault();
                        this.handleLogout();
                    }
                    // Handle other links normally
                    else if (href && href !== '#') {
                        userMenu.classList.add('hidden');
                        // Let the browser handle the navigation
                    }
                });
            });
        }
    }

    // Enhanced logout functionality with emergency fallback
    async handleLogout() {
        if (!confirm('Are you sure you want to logout?')) {
            return;
        }

        try {
            const response = await fetch('/api/auth/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin'
            });

            const data = await response.json();
            
            if (data.success) {
                // Show success message
                this.showToast('Logged out successfully', 'success');
                
                // Redirect after short delay
                setTimeout(() => {
                    window.location.href = data.redirect_url || '/login';
                }, 1000);
            } else {
                throw new Error(data.message || 'Logout failed');
            }
        } catch (error) {
            console.error('Logout error:', error);
            this.showToast('Logout failed, redirecting anyway...', 'warning');
            
            // Emergency fallback: redirect anyway after short delay
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        }
    }

    // Emergency logout function for immediate access
    emergencyLogout() {
        fetch('/api/auth/logout', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        }).then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/login';
            } else {
                // Force logout anyway
                window.location.href = '/login';
            }
        }).catch(() => {
            // Force logout on error
            window.location.href = '/login';
        });
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
    // RECIPIENTS MANAGEMENT FUNCTIONALITY - FIXED
    // ===========================================

    async loadRecipients() {
        try {
            const response = await fetch('/api/recipients');
            if (!response.ok) {
                console.warn('Recipients API not available:', response.status);
                this.recipients = [];
                this.renderRecipients([]);
                this.updateRecipientStats();
                return;
            }
            
            const data = await response.json();
            this.recipients = data || [];
            this.renderRecipients(this.recipients);
            this.updateRecipientStats();
        } catch (error) {
            console.warn('Recipients functionality not available:', error);
            this.recipients = [];
            this.renderRecipients([]);
            this.updateRecipientStats();
            // Don't break the logout functionality - just continue
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

    updateRecipientStats() {
        const totalRecipients = this.recipients.length;
        const activeRecipients = this.recipients.filter(r => r.status === 'active').length;
        
        // Update stats in recipients tab
        this.updateElement('total-recipients', totalRecipients);
        this.updateElement('active-recipients', activeRecipients);
        this.updateElement('inactive-recipients', totalRecipients - activeRecipients);
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
        let modal = document.getElementById('recipient-modal');
        if (!modal) {
            modal = this.createRecipientModal();
            document.body.appendChild(modal);
        }
        
        const content = document.getElementById('recipient-modal-content');
        content.innerHTML = `
            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-lg font-medium text-gray-900">Add New Recipient</h3>
                    <button onclick="dashboard.closeModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <form id="recipient-modal-form" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Name</label>
                        <input type="text" id="modal-recipient-name" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Email Address</label>
                        <input type="email" id="modal-recipient-email" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Category</label>
                        <select id="modal-recipient-category" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                            <option value="General">General</option>
                            <option value="Business">Business</option>
                            <option value="Personal">Personal</option>
                            <option value="Marketing">Marketing</option>
                            <option value="Support">Support</option>
                        </select>
                    </div>
                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="dashboard.closeModal()" class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                            Cancel
                        </button>
                        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700">
                            Add Recipient
                        </button>
                    </div>
                </form>
            </div>
        `;
        
        // Bind form submission
        const form = document.getElementById('recipient-modal-form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.submitRecipientModal();
        });
        
        modal.classList.add('show');
        modal.style.display = 'flex';
    }

    async submitRecipientModal() {
        this.showLoading(true);
        
        const formData = {
            name: document.getElementById('modal-recipient-name').value,
            email: document.getElementById('modal-recipient-email').value,
            category: document.getElementById('modal-recipient-category').value,
            status: 'active'
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
        // Create modal if it doesn't exist
        let modal = document.getElementById('bulk-import-modal');
        if (!modal) {
            modal = this.createBulkImportModal();
            document.body.appendChild(modal);
        }
        
        modal.classList.add('show');
        modal.style.display = 'flex';
    }

    createBulkImportModal() {
        const modal = document.createElement('div');
        modal.id = 'bulk-import-modal';
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
                <div class="space-y-4">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-medium text-gray-900">Bulk Import Recipients</h3>
                        <button onclick="dashboard.closeModal()" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Upload CSV File</label>
                            <div class="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
                                <input type="file" id="csv-file-input" accept=".csv" class="hidden">
                                <button onclick="document.getElementById('csv-file-input').click()" class="text-blue-600 hover:text-blue-700">
                                    <i class="fas fa-upload text-2xl mb-2"></i>
                                    <p>Click to upload CSV file</p>
                                </button>
                            </div>
                        </div>
                        <div class="text-sm text-gray-600">
                            <p><strong>CSV Format:</strong> name,email,category</p>
                            <p><strong>Example:</strong></p>
                            <code class="bg-gray-100 p-2 rounded block mt-2">
                                John Doe,john@example.com,Business<br>
                                Jane Smith,jane@example.com,Marketing
                            </code>
                        </div>
                        <div class="flex justify-end space-x-3">
                            <button onclick="dashboard.closeModal()" class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModal();
            }
        });
        
        return modal;
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

    showEditRecipientModal(recipient) {
        // Create modal if it doesn't exist
        let modal = document.getElementById('recipient-modal');
        if (!modal) {
            modal = this.createRecipientModal();
            document.body.appendChild(modal);
        }
        
        const content = document.getElementById('recipient-modal-content');
        content.innerHTML = `
            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-lg font-medium text-gray-900">Edit Recipient</h3>
                    <button onclick="dashboard.closeModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <form id="recipient-modal-form" class="space-y-4">
                    <input type="hidden" id="modal-recipient-id" value="${recipient.id}">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Name</label>
                        <input type="text" id="modal-recipient-name" value="${recipient.name || ''}" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Email Address</label>
                        <input type="email" id="modal-recipient-email" value="${recipient.email}" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Category</label>
                        <select id="modal-recipient-category" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                            <option value="General" ${recipient.category === 'General' ? 'selected' : ''}>General</option>
                            <option value="Business" ${recipient.category === 'Business' ? 'selected' : ''}>Business</option>
                            <option value="Personal" ${recipient.category === 'Personal' ? 'selected' : ''}>Personal</option>
                            <option value="Marketing" ${recipient.category === 'Marketing' ? 'selected' : ''}>Marketing</option>
                            <option value="Support" ${recipient.category === 'Support' ? 'selected' : ''}>Support</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Status</label>
                        <select id="modal-recipient-status" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                            <option value="active" ${recipient.status === 'active' ? 'selected' : ''}>Active</option>
                            <option value="inactive" ${recipient.status === 'inactive' ? 'selected' : ''}>Inactive</option>
                        </select>
                    </div>
                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="dashboard.closeModal()" class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                            Cancel
                        </button>
                        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700">
                            Update Recipient
                        </button>
                    </div>
                </form>
            </div>
        `;
        
        // Bind form submission
        const form = document.getElementById('recipient-modal-form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.updateRecipientModal();
        });
        
        modal.classList.add('show');
        modal.style.display = 'flex';
    }

    async updateRecipientModal() {
        this.showLoading(true);
        
        const recipientId = document.getElementById('modal-recipient-id').value;
        const formData = {
            name: document.getElementById('modal-recipient-name').value,
            email: document.getElementById('modal-recipient-email').value,
            category: document.getElementById('modal-recipient-category').value,
            status: document.getElementById('modal-recipient-status').value
        };

        try {
            const response = await fetch(`/api/recipients/${recipientId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient updated successfully!', 'success');
                this.loadRecipients();
                this.closeModal();
            } else {
                this.showToast(`Failed to update recipient: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error updating recipient. Please try again.', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    createRecipientModal() {
        const modal = document.createElement('div');
        modal.id = 'recipient-modal';
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
                <div id="recipient-modal-content"></div>
            </div>
        `;
        
        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModal();
            }
        });
        
        return modal;
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
                                <button onclick="dashboard.manageCampaignRecipients(${campaign.id})" class="text-purple-600 hover:text-purple-700" title="Manage Recipients">
                                    <i class="fas fa-users"></i>
                                </button>
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

    // Campaign-Recipient Management
    async manageCampaignRecipients(campaignId) {
        try {
            // Load campaign details and recipients
            const [campaignResponse, recipientsResponse] = await Promise.all([
                fetch(`/api/campaigns/${campaignId}`),
                fetch('/api/recipients')
            ]);
            
            const campaign = await campaignResponse.json();
            const allRecipients = await recipientsResponse.json();
            
            // Load campaign's current recipients
            const campaignRecipientsResponse = await fetch(`/api/campaigns/${campaignId}/recipients`);
            const campaignRecipients = await campaignRecipientsResponse.json();
            
            this.showCampaignRecipientsModal(campaign, allRecipients, campaignRecipients);
        } catch (error) {
            this.showToast('Failed to load campaign recipients', 'error');
        }
    }

    showCampaignRecipientsModal(campaign, allRecipients, campaignRecipients) {
        // Create modal if it doesn't exist
        let modal = document.getElementById('campaign-recipients-modal');
        if (!modal) {
            modal = this.createCampaignRecipientsModal();
            document.body.appendChild(modal);
        }
        
        const assignedIds = campaignRecipients.map(r => r.id);
        
        const content = document.getElementById('campaign-recipients-modal-content');
        content.innerHTML = `
            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-lg font-medium text-gray-900">Manage Recipients - ${campaign.name}</h3>
                    <button onclick="dashboard.closeModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <div class="grid grid-cols-2 gap-6">
                    <!-- Available Recipients -->
                    <div>
                        <h4 class="font-medium text-gray-900 mb-3">Available Recipients (${allRecipients.filter(r => !assignedIds.includes(r.id)).length})</h4>
                        <div class="border rounded-lg max-h-64 overflow-y-auto">
                            ${allRecipients.filter(r => !assignedIds.includes(r.id)).map(recipient => `
                                <div class="p-3 border-b flex justify-between items-center hover:bg-gray-50">
                                    <div>
                                        <p class="font-medium text-sm">${recipient.name || 'Unknown'}</p>
                                        <p class="text-xs text-gray-600">${recipient.email}</p>
                                        <span class="text-xs px-2 py-1 bg-blue-100 text-blue-800 rounded">${recipient.category}</span>
                                    </div>
                                    <button onclick="dashboard.assignRecipientToCampaign(${campaign.id}, ${recipient.id})" 
                                            class="text-green-600 hover:text-green-700" title="Assign">
                                        <i class="fas fa-plus"></i>
                                    </button>
                                </div>
                            `).join('') || '<p class="p-4 text-gray-500 text-center">No available recipients</p>'}
                        </div>
                    </div>
                    
                    <!-- Assigned Recipients -->
                    <div>
                        <h4 class="font-medium text-gray-900 mb-3">Assigned Recipients (${campaignRecipients.length})</h4>
                        <div class="border rounded-lg max-h-64 overflow-y-auto">
                            ${campaignRecipients.map(recipient => `
                                <div class="p-3 border-b flex justify-between items-center hover:bg-gray-50">
                                    <div>
                                        <p class="font-medium text-sm">${recipient.name || 'Unknown'}</p>
                                        <p class="text-xs text-gray-600">${recipient.email}</p>
                                        <span class="text-xs px-2 py-1 bg-green-100 text-green-800 rounded">${recipient.category}</span>
                                    </div>
                                    <button onclick="dashboard.removeRecipientFromCampaign(${campaign.id}, ${recipient.id})" 
                                            class="text-red-600 hover:text-red-700" title="Remove">
                                        <i class="fas fa-minus"></i>
                                    </button>
                                </div>
                            `).join('') || '<p class="p-4 text-gray-500 text-center">No assigned recipients</p>'}
                        </div>
                    </div>
                </div>
                
                <div class="flex justify-between items-center pt-4 border-t">
                    <button onclick="dashboard.assignAllRecipients(${campaign.id})" 
                            class="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700">
                        Assign All Active Recipients
                    </button>
                    <button onclick="dashboard.closeModal()" 
                            class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                        Done
                    </button>
                </div>
            </div>
        `;
        
        modal.classList.add('show');
        modal.style.display = 'flex';
    }

    createCampaignRecipientsModal() {
        const modal = document.createElement('div');
        modal.id = 'campaign-recipients-modal';
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="bg-white rounded-lg p-6 max-w-4xl w-full mx-4 max-h-96 overflow-y-auto">
                <div id="campaign-recipients-modal-content"></div>
            </div>
        `;
        
        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModal();
            }
        });
        
        return modal;
    }

    async assignRecipientToCampaign(campaignId, recipientId) {
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/recipients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: recipientId })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient assigned successfully!', 'success');
                // Refresh the modal
                this.manageCampaignRecipients(campaignId);
                this.loadCampaigns(); // Refresh campaigns list
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to assign recipient', 'error');
        }
    }

    async removeRecipientFromCampaign(campaignId, recipientId) {
        if (!confirm('Remove this recipient from the campaign?')) return;
        
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/recipients/${recipientId}`, {
                method: 'DELETE'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Recipient removed successfully!', 'success');
                // Refresh the modal
                this.manageCampaignRecipients(campaignId);
                this.loadCampaigns(); // Refresh campaigns list
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to remove recipient', 'error');
        }
    }

    async assignAllRecipients(campaignId) {
        if (!confirm('Assign all active recipients to this campaign?')) return;
        
        try {
            const response = await fetch(`/api/campaigns/${campaignId}/recipients/assign-all`, {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast(`Successfully assigned ${result.count} recipients!`, 'success');
                // Refresh the modal
                this.manageCampaignRecipients(campaignId);
                this.loadCampaigns(); // Refresh campaigns list
            } else {
                this.showToast('Error: ' + result.message, 'error');
            }
        } catch (error) {
            this.showToast('Failed to assign recipients', 'error');
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
            
            // Create modal if it doesn't exist
            let modal = document.getElementById('campaign-modal');
            if (!modal) {
                modal = this.createModal();
                document.body.appendChild(modal);
            }
            
            const content = document.getElementById('modal-content');
            content.innerHTML = `
                <div class="space-y-4">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-medium text-gray-900">Campaign Details</h3>
                        <button onclick="dashboard.closeModal()" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
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
                        <div>
                            <h4 class="font-medium text-gray-900">Industry</h4>
                            <p class="text-sm text-gray-600">${campaign.industry || 'N/A'}</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Daily Volume</h4>
                            <p class="text-sm text-gray-600">${campaign.daily_volume || 0} emails/day</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Emails Sent</h4>
                            <p class="text-sm text-gray-600">${campaign.emails_sent || 0}</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Success Rate</h4>
                            <p class="text-sm text-gray-600">${campaign.success_rate || 0}%</p>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900">Recipients</h4>
                            <p class="text-sm text-gray-600">${campaign.recipient_count || 0} assigned</p>
                        </div>
                    </div>
                </div>
            `;
            
            modal.classList.add('show');
            modal.style.display = 'flex';
        } catch (error) {
            this.showToast('Failed to load campaign details', 'error');
        }
    }

    createModal() {
        const modal = document.createElement('div');
        modal.id = 'campaign-modal';
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
                <div id="modal-content"></div>
            </div>
        `;
        
        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModal();
            }
        });
        
        return modal;
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
            'campaign-modal',
            'recipient-modal', 
            'bulk-import-modal',
            'campaign-recipients-modal'
        ];
        
        modals.forEach(modalId => {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('show');
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

// Global logout function (used by base.html) - Enhanced with emergency fallback
function handleLogout() {
    if (window.dashboard) {
        window.dashboard.handleLogout();
    } else {
        // Emergency fallback if dashboard isn't initialized
        if (confirm('Are you sure you want to logout?')) {
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            }).then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/login';
                } else {
                    window.location.href = '/login';
                }
            }).catch(() => {
                window.location.href = '/login';
            });
        }
    }
}

// Initialize dashboard
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmailWarmupDashboard();
    window.dashboard = dashboard;
    
    // Set global reference for base.html with emergency fallback
    window.handleLogout = handleLogout;
    
    // Override the existing logout function with our enhanced version
    window.handleLogout = () => {
        if (dashboard) {
            dashboard.handleLogout();
        } else {
            // Emergency logout if dashboard fails
            dashboard.emergencyLogout();
        }
    };
    
    console.log('Dashboard initialized successfully with Recipients Management functionality and enhanced logout');
});
