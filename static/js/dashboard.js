// Simple Dashboard JS - Fixed Version
class EmailWarmupDashboard {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadCampaigns();
        this.loadDashboardStats();
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
                <div class="bg-white p-6 rounded-lg shadow-lg mb-4">
                    <div class="flex justify-between items-center">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">${campaign.name}</h3>
                            <p class="text-sm text-gray-600">${campaign.email}</p>
                            <p class="text-sm text-gray-500">${campaign.provider}</p>
                            <span class="inline-flex px-2 py-1 text-xs font-medium rounded-full ${campaign.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">
                                ${campaign.status}
                            </span>
                        </div>
                        <div class="flex space-x-2">
                            <button onclick="dashboard.startCampaign(${campaign.id})" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">
                                Start
                            </button>
                            <button onclick="dashboard.deleteCampaign(${campaign.id})" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    async handleFormSubmit(event) {
        event.preventDefault();
        
        const formData = {
            name: document.getElementById('campaign-name').value,
            email: document.getElementById('email-address').value,
            provider: document.getElementById('email-provider').value,
            username: document.getElementById('smtp-username').value,
            password: document.getElementById('smtp-password').value,
            industry: document.getElementById('industry').value,
            daily_volume: document.getElementById('daily-volume').value,
            warmup_days: document.getElementById('warmup-days').value
        };

        try {
            const response = await fetch('/api/campaigns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (result.success) {
                alert('Campaign created successfully!');
                document.getElementById('campaign-form').reset();
                this.loadCampaigns();
                this.loadDashboardStats();
                this.switchTab('campaigns');
            } else {
                alert(`Failed to create campaign: ${result.message}`);
            }
        } catch (error) {
            alert('Error creating campaign. Please try again.');
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
                alert('Campaign started successfully!');
                this.loadCampaigns();
                this.loadDashboardStats();
            } else {
                alert(`Failed to start campaign: ${result.message}`);
            }
        } catch (error) {
            alert('Error starting campaign.');
        }
    }

    async deleteCampaign(campaignId) {
        if (confirm('Are you sure you want to delete this campaign?')) {
            try {
                const response = await fetch(`/api/campaigns/${campaignId}`, {
                    method: 'DELETE'
                });

                const result = await response.json();
                
                if (result.success) {
                    alert('Campaign deleted successfully!');
                    this.loadCampaigns();
                    this.loadDashboardStats();
                } else {
                    alert(`Failed to delete campaign: ${result.message}`);
                }
            } catch (error) {
                alert('Error deleting campaign.');
            }
        }
    }
}

// Initialize dashboard
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmailWarmupDashboard();
});

// Add this function to your dashboard.js
async loadAnalytics() {
    try {
        const response = await fetch('/api/campaigns/1/stats'); // Assuming campaign ID 1
        const stats = await response.json();
        
        const analyticsContainer = document.querySelector('#analytics-tab .text-center');
        if (analyticsContainer && stats) {
            analyticsContainer.innerHTML = `
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
            `;
        }
    } catch (error) {
        console.error('Failed to load analytics:', error);
    }
}
