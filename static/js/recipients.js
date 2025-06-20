// Recipients Management JavaScript
class RecipientsManager {
    constructor() {
        this.currentPage = 1;
        this.perPage = 20;
        this.filters = {
            search: '',
            industry: '',
            active_only: false
        };
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadRecipients();
        this.loadStats();
    }

    bindEvents() {
        // Add recipient form
        const addForm = document.getElementById('add-recipient-form');
        if (addForm) {
            addForm.addEventListener('submit', this.handleAddRecipient.bind(this));
        }

        // Bulk import form
        const bulkForm = document.getElementById('bulk-import-form');
        if (bulkForm) {
            bulkForm.addEventListener('submit', this.handleBulkImport.bind(this));
        }

        // Search input with debounce
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.filters.search = e.target.value;
                    this.currentPage = 1;
                    this.loadRecipients();
                }, 500);
            });
        }
    }

    async loadRecipients() {
        try {
            this.showLoading(true);
            
            const params = new URLSearchParams({
                page: this.currentPage,
                per_page: this.perPage,
                search: this.filters.search,
                industry: this.filters.industry,
                active_only: this.filters.active_only
            });

            const response = await fetch(`/api/recipients?${params}`);
            const data = await response.json();

            if (response.ok) {
                this.renderRecipients(data.recipients);
                this.renderPagination(data.pagination);
                this.updateIndustryFilter(data.industries);
            } else {
                this.showToast('Failed to load recipients', 'error');
            }
        } catch (error) {
            console.error('Error loading recipients:', error);
            this.showToast('Error loading recipients', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/api/recipients/stats');
            const data = await response.json();

            if (response.ok) {
                this.updateElement('total-recipients', data.total_recipients);
                this.updateElement('active-recipients', data.active_recipients);
                this.updateElement('recently-emailed', data.recently_emailed);
                this.updateElement('avg-success-rate', Math.round(data.average_success_rate) + '%');
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    renderRecipients(recipients) {
        const tbody = document.getElementById('recipients-table-body');
        if (!tbody) return;

        if (recipients.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="px-6 py-12 text-center text-gray-500">
                        <i class="fas fa-users text-4xl mb-4"></i>
                        <p class="text-lg">No recipients found</p>
                        <p class="text-sm">Try adjusting your filters or add some recipients</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = recipients.map(recipient => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                        <div class="flex-shrink-0 h-10 w-10">
                            <div class="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                                <span class="text-blue-600 font-medium text-sm">
                                    ${recipient.name.charAt(0).toUpperCase()}
                                </span>
                            </div>
                        </div>
                        <div class="ml-4">
                            <div class="text-sm font-medium text-gray-900">${recipient.name}</div>
                            <div class="text-sm text-gray-500">${recipient.email}</div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        ${recipient.industry.replace('_', ' ').toUpperCase()}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${recipient.email_count}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${recipient.success_rate}%
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${recipient.last_emailed ? new Date(recipient.last_emailed).toLocaleDateString() : 'Never'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        recipient.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }">
                        ${recipient.is_active ? 'Active' : 'Inactive'}
                    </span>
                </td>
                ${userIsAdmin ? `
                    <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <button onclick="recipientsManager.editRecipient(${recipient.id})" 
                                class="text-blue-600 hover:text-blue-900 mr-3">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button onclick="recipientsManager.toggleRecipientStatus(${recipient.id})" 
                                class="text-yellow-600 hover:text-yellow-900 mr-3">
                            <i class="fas fa-toggle-${recipient.is_active ? 'on' : 'off'}"></i>
                        </button>
                        <button onclick="recipientsManager.deleteRecipient(${recipient.id})" 
                                class="text-red-600 hover:text-red-900">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                ` : ''}
            </tr>
        `).join('');
    }

    renderPagination(pagination) {
        const container = document.getElementById('pagination-container');
        if (!container || !pagination) return;

        const { page, pages, total, has_prev, has_next } = pagination;

        container.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="text-sm text-gray-700">
                    Showing page ${page} of ${pages} (${total} total recipients)
                </div>
                <div class="flex space-x-2">
                    <button onclick="recipientsManager.goToPage(1)" 
                            ${!has_prev ? 'disabled' : ''} 
                            class="px-3 py-1 border rounded text-sm ${!has_prev ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}">
                        First
                    </button>
                    <button onclick="recipientsManager.goToPage(${page - 1})" 
                            ${!has_prev ? 'disabled' : ''} 
                            class="px-3 py-1 border rounded text-sm ${!has_prev ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}">
                        Previous
                    </button>
                    <span class="px-3 py-1 bg-blue-600 text-white rounded text-sm">
                        ${page}
                    </span>
                    <button onclick="recipientsManager.goToPage(${page + 1})" 
                            ${!has_next ? 'disabled' : ''} 
                            class="px-3 py-1 border rounded text-sm ${!has_next ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}">
                        Next
                    </button>
                    <button onclick="recipientsManager.goToPage(${pages})" 
                            ${!has_next ? 'disabled' : ''} 
                            class="px-3 py-1 border rounded text-sm ${!has_next ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-50'}">
                        Last
                    </button>
                </div>
            </div>
        `;
    }

    updateIndustryFilter(industries) {
        const select = document.getElementById('industry-filter');
        if (!select) return;

        // Keep current selection
        const currentValue = select.value;
        
        // Clear and rebuild options
        select.innerHTML = '<option value="">All Industries</option>';
        
        industries.forEach(industry => {
            const option = document.createElement('option');
            option.value = industry;
            option.textContent = industry.replace('_', ' ').toUpperCase();
            if (industry === currentValue) option.selected = true;
            select.appendChild(option);
        });
    }

    async handleAddRecipient(event) {
        event.preventDefault();
        
        const formData = {
            email: document.getElementById('recipient-email').value,
            name: document.getElementById('recipient-name').value,
            industry: document.getElementById('recipient-industry').value,
            notes: document.getElementById('recipient-notes').value,
            responds: document.getElementById('recipient-responds').checked
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
                this.closeAddRecipientModal();
                document.getElementById('add-recipient-form').reset();
                this.loadRecipients();
                this.loadStats();
            } else {
                this.showToast(`Failed to add recipient: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Error adding recipient', 'error');
        }
    }

    async handleBulkImport(event) {
        event.preventDefault();
        
        const dataText = document.getElementById('bulk-recipients-data').value;
        
        try {
            const recipients = JSON.parse(dataText);
            
            if (!Array.isArray(recipients)) {
                throw new Error('Data must be an array');
            }

            const response = await fetch('/api/recipients/bulk-add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipients })
            });

            const result = await response.json();

            if (result.success) {
                this.showToast(`Imported ${result.added} recipients, skipped ${result.skipped}`, 'success');
                this.closeBulkImportModal();
                document.getElementById('bulk-import-form').reset();
                this.loadRecipients();
                this.loadStats();
            } else {
                this.showToast(`Bulk import failed: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showToast('Invalid JSON format', 'error');
        }
    }

    async toggleRecipientStatus(recipientId) {
        try {
            const response = await fetch(`/api/recipients/${recipientId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: 'toggle' })
            });

            const result = await response.json();

            if (result.success) {
                this.showToast('Recipient status updated', 'success');
                this.loadRecipients();
                this.loadStats();
            } else {
                this.showToast('Failed to update recipient', 'error');
            }
        } catch (error) {
            this.showToast('Error updating recipient', 'error');
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
                this.showToast('Recipient deleted successfully', 'success');
                this.loadRecipients();
                this.loadStats();
            } else {
                this.showToast('Failed to delete recipient', 'error');
            }
        } catch (error) {
            this.showToast('Error deleting recipient', 'error');
        }
    }

    // Utility functions
    goToPage(page) {
        this.currentPage = page;
        this.loadRecipients();
    }

    applyFilters() {
        this.filters.industry = document.getElementById('industry-filter').value;
        this.filters.active_only = document.getElementById('status-filter').value === 'true';
        this.currentPage = 1;
        this.loadRecipients();
    }

    refreshRecipients() {
        this.loadRecipients();
        this.loadStats();
    }

    showAddRecipientModal() {
        document.getElementById('add-recipient-modal').classList.remove('hidden');
        document.getElementById('add-recipient-modal').classList.add('flex');
    }

    closeAddRecipientModal() {
        document.getElementById('add-recipient-modal').classList.add('hidden');
        document.getElementById('add-recipient-modal').classList.remove('flex');
    }

    showBulkImportModal() {
        document.getElementById('bulk-import-modal').classList.remove('hidden');
        document.getElementById('bulk-import-modal').classList.add('flex');
    }

    closeBulkImportModal() {
        document.getElementById('bulk-import-modal').classList.add('hidden');
        document.getElementById('bulk-import-modal').classList.remove('flex');
    }

    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            if (show) {
                overlay.classList.remove('hidden');
                overlay.classList.add('flex');
            } else {
                overlay.classList.add('hidden');
                overlay.classList.remove('flex');
            }
        }
    }

    showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `px-4 py-3 rounded-lg shadow-lg max-w-sm transition-all duration-300 transform translate-x-full opacity-0`;
        
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
}

// Global functions for HTML onclick handlers
function showAddRecipientModal() {
    if (window.recipientsManager) {
        window.recipientsManager.showAddRecipientModal();
    }
}

function closeAddRecipientModal() {
    if (window.recipientsManager) {
        window.recipientsManager.closeAddRecipientModal();
    }
}

function showBulkImportModal() {
    if (window.recipientsManager) {
        window.recipientsManager.showBulkImportModal();
    }
}

function closeBulkImportModal() {
    if (window.recipientsManager) {
        window.recipientsManager.closeBulkImportModal();
    }
}

function refreshRecipients() {
    if (window.recipientsManager) {
        window.recipientsManager.refreshRecipients();
    }
}

function applyFilters() {
    if (window.recipientsManager) {
        window.recipientsManager.applyFilters();
    }
}

// Check if user is admin (passed from template)
const userIsAdmin = {{ current_user.is_admin() | tojson }};

// Initialize recipients manager
let recipientsManager;
document.addEventListener('DOMContentLoaded', function() {
    recipientsManager = new RecipientsManager();
    window.recipientsManager = recipientsManager;
    
    console.log('Recipients manager initialized successfully');
});
