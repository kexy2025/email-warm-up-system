// dashboard.js - ALL JAVASCRIPT FUNCTIONS
let currentUser = null;

// Form switching functions
function showLoginForm() {
    hideAllForms();
    document.getElementById('login-form').classList.remove('hidden');
}

function showRegisterForm() {
    hideAllForms();
    document.getElementById('register-form').classList.remove('hidden');
}

function showForgotPassword() {
    hideAllForms();
    document.getElementById('forgot-password-form').classList.remove('hidden');
}

function showResetPasswordForm() {
    hideAllForms();
    document.getElementById('reset-password-form').classList.remove('hidden');
}

function hideAllForms() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('forgot-password-form').classList.add('hidden');
    document.getElementById('reset-password-form').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('dashboard-content').classList.remove('hidden');
    document.getElementById('logout-btn').classList.remove('hidden');
    loadDashboard();
}

function showAuth() {
    document.getElementById('auth-container').classList.remove('hidden');
    document.getElementById('dashboard-content').classList.add('hidden');
    document.getElementById('logout-btn').classList.add('hidden');
}

// Modal functions
function showCampaignModal() {
    document.getElementById('create-campaign-modal').classList.remove('hidden');
}

function hideCampaignModal() {
    document.getElementById('create-campaign-modal').classList.add('hidden');
    document.getElementById('create-campaign-form').reset();
    document.getElementById('smtp-validation-result').classList.add('hidden');
}

// Provider detection
async function detectProvider() {
    const email = document.getElementById('campaign-email').value;
    if (!email) return;

    try {
        const response = await fetch('/api/detect-provider', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await response.json();
        updateProviderConfig(data.config);
        
    } catch (error) {
        console.error('Provider detection failed:', error);
    }
}

function updateProviderConfig(config = null) {
    if (config) {
        document.getElementById('smtp-host').value = config.smtp_host || '';
        document.getElementById('smtp-port').value = config.smtp_port || 587;
        document.getElementById('smtp-username').value = document.getElementById('campaign-email').value || '';
    }
}

// SMTP validation
async function validateSMTP() {
    const email = document.getElementById('campaign-email').value;
    const password = document.getElementById('smtp-password').value;
    const smtpHost = document.getElementById('smtp-host').value;
    const smtpPort = document.getElementById('smtp-port').value;
    const smtpUsername = document.getElementById('smtp-username').value;
    const provider = document.getElementById('campaign-provider').value;

    if (!email || !password || !smtpHost) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    try {
        const response = await fetch('/api/test-smtp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                smtp_host: smtpHost,
                smtp_port: smtpPort,
                smtp_username: smtpUsername,
                provider
            })
        });

        const result = await response.json();
        const resultDiv = document.getElementById('smtp-validation-result');
        
        if (result.success) {
            resultDiv.className = 'mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded';
            resultDiv.innerHTML = `<i class="fas fa-check-circle mr-2"></i>${result.message}`;
        } else {
            resultDiv.className = 'mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded';
            resultDiv.innerHTML = `<i class="fas fa-times-circle mr-2"></i>${result.message}`;
        }
        
        resultDiv.classList.remove('hidden');
        
    } catch (error) {
        showNotification('SMTP validation failed', 'error');
    }
}

// Notification function
function showNotification(message, type) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    
    const bgColor = type === 'success' ? 'bg-green-100 border-green-400 text-green-700' : 
                   type === 'warning' ? 'bg-yellow-100 border-yellow-400 text-yellow-700' :
                   'bg-red-100 border-red-400 text-red-700';
    
    const icon = type === 'success' ? 'fa-check-circle' : 
                type === 'warning' ? 'fa-exclamation-triangle' : 'fa-times-circle';
    
    notification.className = `border-l-4 p-4 mb-4 rounded-r-md ${bgColor}`;
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${icon} mr-2"></i>
            <span>${message}</span>
        </div>
    `;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Load dashboard data
async function loadDashboard() {
    try {
        const response = await fetch('/api/dashboard/stats');
        const stats = await response.json();
        
        document.getElementById('active-campaigns-count').textContent = stats.active_campaigns;
        document.getElementById('emails-sent-today').textContent = stats.emails_sent_today;
        document.getElementById('avg-reputation-score').textContent = stats.avg_reputation_score;
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loaded');
    
    // Check for reset token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('token');
    
    if (resetToken) {
        document.getElementById('reset-token').value = resetToken;
        showResetPasswordForm();
    }

    // Login form
    document.getElementById('login-form-element').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (data.success) {
                currentUser = data.user;
                document.getElementById('user-info').textContent = `Welcome, ${data.user.username}`;
                showNotification(data.message, 'success');
                showDashboard();
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Login failed. Please try again.', 'error');
        }
    });

    // Register form
    document.getElementById('register-form-element').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password }),
            });

            const data = await response.json();

            if (data.success) {
                currentUser = data.user;
                document.getElementById('user-info').textContent = `Welcome, ${data.user.username}`;
                showNotification(data.message, 'success');
                showDashboard();
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Registration failed. Please try again.', 'error');
        }
    });

    // Forgot password form
    document.getElementById('forgot-password-form-element').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('forgot-email').value;

        try {
            const response = await fetch('/api/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message, 'success');
                if (data.reset_token) {
                    document.getElementById('reset-token').value = data.reset_token;
                    showResetPasswordForm();
                }
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Request failed. Please try again.', 'error');
        }
    });

    // Reset password form
    document.getElementById('reset-password-form-element').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = document.getElementById('reset-token').value;
        const password = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;

        if (password !== confirmPassword) {
            showNotification('Passwords do not match', 'error');
            return;
        }

        try {
            const response = await fetch('/api/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, password }),
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message, 'success');
                showLoginForm();
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Reset failed. Please try again.', 'error');
        }
    });

    // Create campaign button
    document.getElementById('create-campaign-btn').addEventListener('click', function() {
        showCampaignModal();
    });

    // Close modal buttons
    document.getElementById('close-modal-btn').addEventListener('click', hideCampaignModal);
    document.getElementById('cancel-campaign-btn').addEventListener('click', hideCampaignModal);

    // Validate SMTP button
    document.getElementById('validate-smtp-btn').addEventListener('click', validateSMTP);

    // Create campaign form
    document.getElementById('create-campaign-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            name: document.getElementById('campaign-name').value,
            email: document.getElementById('campaign-email').value,
            smtp_host: document.getElementById('smtp-host').value,
            smtp_port: document.getElementById('smtp-port').value,
            smtp_username: document.getElementById('smtp-username').value,
            smtp_password: document.getElementById('smtp-password').value,
            provider: document.getElementById('campaign-provider').value
        };

        try {
            const response = await fetch('/api/campaigns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message, 'success');
                hideCampaignModal();
                loadDashboard();
            } else {
                showNotification(data.message, 'error');
            }
        } catch (error) {
            showNotification('Campaign creation failed', 'error');
        }
    });

    // Logout button
    document.getElementById('logout-btn').addEventListener('click', async () => {
        try {
            await fetch('/api/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            currentUser = null;
            document.getElementById('user-info').textContent = '';
            showNotification('Logged out successfully', 'success');
            showAuth();
        } catch (error) {
            showNotification('Logout failed', 'error');
        }
    });
});
