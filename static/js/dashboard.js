// Dashboard JavaScript Module
class EmailWarmupDashboard {
    constructor() {
        this.currentUser = null;
        this.smtpValidated = false;
        this.csrfToken = null;
        this.init();
    }

    init() {
        this.setupCSRF();
        this.setupEventListeners();
        this.checkURLParams();
        this.loadDashboardIfLoggedIn();
    }

    setupCSRF() {
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        this.csrfToken = metaToken ? metaToken.getAttribute('content') : null;
    }

    setupEventListeners() {
        // Form submissions
        document.getElementById('login-form-element')?.addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('register-form-element')
