/**
 * Frank Authentication Server - Main JavaScript
 * General utilities and functionality for the authentication server
 */

// Initialize the application when DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize tooltips
    initTooltips();

    // Initialize alerts
    initAlerts();

    // Setup form validation
    setupFormValidation();

    // Handle dark mode toggle
    setupDarkMode();
});

/**
 * Initialize tooltip functionality
 */
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');

    tooltips.forEach(tooltip => {
        tooltip.addEventListener('mouseenter', () => {
            const content = tooltip.getAttribute('data-tooltip');
            const tooltipElement = document.createElement('div');
            tooltipElement.classList.add('tooltip');
            tooltipElement.textContent = content;

            const rect = tooltip.getBoundingClientRect();
            tooltipElement.style.top = `${rect.top - 10}px`;
            tooltipElement.style.left = `${rect.left + rect.width / 2}px`;
            tooltipElement.style.transform = 'translate(-50%, -100%)';

            document.body.appendChild(tooltipElement);

            setTimeout(() => {
                tooltipElement.classList.add('tooltip-visible');
            }, 10);

            tooltip.addEventListener('mouseleave', () => {
                tooltipElement.classList.remove('tooltip-visible');
                setTimeout(() => {
                    document.body.removeChild(tooltipElement);
                }, 200);
            }, { once: true });
        });
    });
}

/**
 * Initialize dismissible alerts
 */
function initAlerts() {
    const alerts = document.querySelectorAll('.alert .close');

    alerts.forEach(closeBtn => {
        closeBtn.addEventListener('click', () => {
            const alert = closeBtn.closest('.alert');
            alert.classList.add('fade');
            setTimeout(() => {
                alert.style.display = 'none';
            }, 150);
        });
    });

    // Auto-dismiss success and info alerts after 5 seconds
    const autoDismissAlerts = document.querySelectorAll('.alert-success, .alert-info');
    autoDismissAlerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            setTimeout(() => {
                alert.style.display = 'none';
            }, 150);
        }, 5000);
    });
}

/**
 * Setup form validation
 */
function setupFormValidation() {
    const forms = document.querySelectorAll('form[data-validate]');

    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            if (!validateForm(form)) {
                e.preventDefault();
                return false;
            }
        });

        // Real-time validation
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', () => {
                validateInput(input);
            });

            input.addEventListener('input', () => {
                // Clear validation errors on input
                const formGroup = input.closest('.form-group');
                if (formGroup.classList.contains('has-error')) {
                    formGroup.classList.remove('has-error');
                    const errorMessage = formGroup.querySelector('.error-message');
                    if (errorMessage) {
                        errorMessage.remove();
                    }
                }
            });
        });
    });
}

/**
 * Validate an entire form
 * @param {HTMLFormElement} form - The form to validate
 * @returns {boolean} - Whether the form is valid
 */
function validateForm(form) {
    const inputs = form.querySelectorAll('input, select, textarea');
    let isValid = true;

    inputs.forEach(input => {
        if (!validateInput(input)) {
            isValid = false;
        }
    });

    return isValid;
}

/**
 * Validate a single input field
 * @param {HTMLInputElement} input - The input to validate
 * @returns {boolean} - Whether the input is valid
 */
function validateInput(input) {
    const formGroup = input.closest('.form-group');
    const value = input.value.trim();
    let isValid = true;
    let errorMessage = '';

    // Remove any existing error message
    const existingError = formGroup.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    formGroup.classList.remove('has-error');

    // Required validation
    if (input.hasAttribute('required') && value === '') {
        isValid = false;
        errorMessage = 'This field is required';
    }

    // Email validation
    if (input.type === 'email' && value !== '' && !isValidEmail(value)) {
        isValid = false;
        errorMessage = 'Please enter a valid email address';
    }

    // Password validation
    if (input.type === 'password' && input.hasAttribute('data-min-length')) {
        const minLength = parseInt(input.getAttribute('data-min-length'), 10);
        if (value.length < minLength) {
            isValid = false;
            errorMessage = `Password must be at least ${minLength} characters`;
        }
    }

    // Password confirmation validation
    if (input.hasAttribute('data-matches')) {
        const matchSelector = input.getAttribute('data-matches');
        const matchInput = document.querySelector(matchSelector);
        if (matchInput && value !== matchInput.value) {
            isValid = false;
            errorMessage = 'Passwords do not match';
        }
    }

    // Display error message if validation failed
    if (!isValid) {
        formGroup.classList.add('has-error');
        const errorElement = document.createElement('div');
        errorElement.classList.add('error-message');
        errorElement.textContent = errorMessage;
        formGroup.appendChild(errorElement);
    }

    return isValid;
}

/**
 * Validate email format
 * @param {string} email - The email to validate
 * @returns {boolean} - Whether the email is valid
 */
function isValidEmail(email) {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

/**
 * Setup dark mode toggle
 */
function setupDarkMode() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    if (!darkModeToggle) return;

    // Check user preference
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const storedTheme = localStorage.getItem('theme');

    // Set initial state
    if (storedTheme === 'dark' || (!storedTheme && prefersDarkMode)) {
        document.documentElement.classList.add('dark-mode');
        darkModeToggle.checked = true;
    }

    // Handle toggle change
    darkModeToggle.addEventListener('change', () => {
        if (darkModeToggle.checked) {
            document.documentElement.classList.add('dark-mode');
            localStorage.setItem('theme', 'dark');
        } else {
            document.documentElement.classList.remove('dark-mode');
            localStorage.setItem('theme', 'light');
        }
    });
}

/**
 * Show a loading spinner
 * @param {HTMLElement} container - The container to add the loading spinner to
 */
function showLoading(container) {
    container.classList.add('loading-container');

    const overlay = document.createElement('div');
    overlay.classList.add('loading-overlay');

    const spinner = document.createElement('div');
    spinner.classList.add('loading-spinner');

    overlay.appendChild(spinner);
    container.appendChild(overlay);
}

/**
 * Hide the loading spinner
 * @param {HTMLElement} container - The container to remove the loading spinner from
 */
function hideLoading(container) {
    container.classList.remove('loading-container');

    const overlay = container.querySelector('.loading-overlay');
    if (overlay) {
        container.removeChild(overlay);
    }
}

/**
 * Make an API request
 * @param {string} url - The URL to request
 * @param {Object} options - Fetch options
 * @returns {Promise} - The fetch promise
 */
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        credentials: 'same-origin'
    };

    const fetchOptions = { ...defaultOptions, ...options };

    try {
        const response = await fetch(url, fetchOptions);
        const contentType = response.headers.get('content-type');

        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();

            if (!response.ok) {
                throw { status: response.status, data };
            }

            return data;
        } else {
            const text = await response.text();

            if (!response.ok) {
                throw { status: response.status, text };
            }

            return text;
        }
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

/**
 * Show a notification
 * @param {string} message - The message to display
 * @param {string} type - The type of notification (success, error, warning, info)
 * @param {number} duration - How long to show the notification (in ms)
 */
function showNotification(message, type = 'info', duration = 5000) {
    const notificationContainer = document.getElementById('notification-container');

    // Create container if it doesn't exist
    if (!notificationContainer) {
        const container = document.createElement('div');
        container.id = 'notification-container';
        document.body.appendChild(container);
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.classList.add('notification', `notification-${type}`);
    notification.innerHTML = `
    <div class="notification-content">
      <span class="notification-message">${message}</span>
      <button class="notification-close">&times;</button>
    </div>
  `;

    // Add to container
    document.getElementById('notification-container').appendChild(notification);

    // Show with animation
    setTimeout(() => {
        notification.classList.add('notification-show');
    }, 10);

    // Setup close button
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.classList.remove('notification-show');
        setTimeout(() => {
            notification.remove();
        }, 300);
    });

    // Auto-dismiss after duration
    if (duration) {
        setTimeout(() => {
            notification.classList.remove('notification-show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, duration);
    }
}