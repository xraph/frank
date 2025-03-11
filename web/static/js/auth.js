/**
 * Frank Authentication Server - Auth JavaScript
 * Handle authentication-specific functionality
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize login form
    initLoginForm();

    // Initialize registration form
    initRegisterForm();

    // Initialize passwordless authentication
    initPasswordlessAuth();

    // Initialize MFA components
    initMFAComponents();

    // Initialize password reset
    initPasswordReset();

    // Initialize organization selector
    initOrganizationSelector();
});

/**
 * Initialize the login form
 */
function initLoginForm() {
    const loginForm = document.getElementById('login-form');
    if (!loginForm) return;

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(loginForm)) {
            return;
        }

        const formData = new FormData(loginForm);
        const email = formData.get('email');
        const password = formData.get('password');
        const rememberMe = formData.get('remember_me') === 'on';

        try {
            showLoading(loginForm);

            const response = await apiRequest('/api/v1/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    email,
                    password,
                    remember_me: rememberMe
                })
            });

            // Check if MFA is required
            if (response.mfa_required) {
                window.location.href = '/mfa?session=' + response.session_id;
                return;
            }

            // Redirect to dashboard or specified redirect_url
            const urlParams = new URLSearchParams(window.location.search);
            const redirectUrl = urlParams.get('redirect_url') || '/dashboard';
            window.location.href = redirectUrl;

        } catch (error) {
            hideLoading(loginForm);

            if (error.data && error.data.error) {
                showLoginError(error.data.error.message || 'Invalid credentials');
            } else {
                showLoginError('An error occurred. Please try again.');
            }
        }
    });
}

/**
 * Display login error message
 * @param {string} message - Error message to display
 */
function showLoginError(message) {
    const errorContainer = document.getElementById('login-error');
    if (errorContainer) {
        errorContainer.textContent = message;
        errorContainer.style.display = 'block';
    } else {
        showNotification(message, 'error');
    }
}

/**
 * Initialize the registration form
 */
function initRegisterForm() {
    const registerForm = document.getElementById('register-form');
    if (!registerForm) return;

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(registerForm)) {
            return;
        }

        const formData = new FormData(registerForm);
        const email = formData.get('email');
        const password = formData.get('password');
        const firstName = formData.get('first_name');
        const lastName = formData.get('last_name');
        const organizationId = formData.get('organization_id');

        try {
            showLoading(registerForm);

            const response = await apiRequest('/api/v1/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    email,
                    password,
                    first_name: firstName,
                    last_name: lastName,
                    organization_id: organizationId || undefined
                })
            });

            // Check if email verification is required
            if (response.email_verification_required) {
                window.location.href = '/verify-email?email=' + encodeURIComponent(email);
                return;
            }

            // Redirect to dashboard or specified redirect_url
            const urlParams = new URLSearchParams(window.location.search);
            const redirectUrl = urlParams.get('redirect_url') || '/dashboard';
            window.location.href = redirectUrl;

        } catch (error) {
            hideLoading(registerForm);

            if (error.data && error.data.error) {
                showRegistrationError(error.data.error.message || 'Registration failed');
            } else {
                showRegistrationError('An error occurred. Please try again.');
            }
        }
    });
}

/**
 * Display registration error message
 * @param {string} message - Error message to display
 */
function showRegistrationError(message) {
    const errorContainer = document.getElementById('register-error');
    if (errorContainer) {
        errorContainer.textContent = message;
        errorContainer.style.display = 'block';
    } else {
        showNotification(message, 'error');
    }
}

/**
 * Initialize passwordless authentication
 */
function initPasswordlessAuth() {
    // Email passwordless login
    initEmailPasswordless();

    // SMS passwordless login
    initSMSPasswordless();
}

/**
 * Initialize email passwordless login
 */
function initEmailPasswordless() {
    const emailPasswordlessForm = document.getElementById('email-passwordless-form');
    if (!emailPasswordlessForm) return;

    emailPasswordlessForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(emailPasswordlessForm)) {
            return;
        }

        const formData = new FormData(emailPasswordlessForm);
        const email = formData.get('email');

        try {
            showLoading(emailPasswordlessForm);

            const response = await apiRequest('/api/v1/auth/passwordless/email', {
                method: 'POST',
                body: JSON.stringify({
                    email,
                    redirect_url: window.location.href
                })
            });

            hideLoading(emailPasswordlessForm);

            // Show success message
            const formContainer = emailPasswordlessForm.parentElement;
            formContainer.innerHTML = `
        <div class="magic-link-sent">
          <div class="magic-link-icon">✉️</div>
          <h3>Magic Link Sent!</h3>
          <p>We've sent a magic link to</p>
          <div class="magic-link-email">${email}</div>
          <p>Check your email and click the link to sign in.</p>
          <div class="magic-link-resend">
            <button type="button" class="btn btn-outline" id="resend-magic-link">Resend Magic Link</button>
          </div>
        </div>
      `;

            // Setup resend button
            const resendButton = document.getElementById('resend-magic-link');
            if (resendButton) {
                resendButton.addEventListener('click', () => {
                    window.location.reload();
                });
            }

        } catch (error) {
            hideLoading(emailPasswordlessForm);

            if (error.data && error.data.error) {
                showNotification(error.data.error.message || 'Failed to send magic link', 'error');
            } else {
                showNotification('An error occurred. Please try again.', 'error');
            }
        }
    });
}

/**
 * Initialize SMS passwordless login
 */
function initSMSPasswordless() {
    const smsPasswordlessForm = document.getElementById('sms-passwordless-form');
    if (!smsPasswordlessForm) return;

    smsPasswordlessForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(smsPasswordlessForm)) {
            return;
        }

        const formData = new FormData(smsPasswordlessForm);
        const phoneNumber = formData.get('phone_number');

        try {
            showLoading(smsPasswordlessForm);

            const response = await apiRequest('/api/v1/auth/passwordless/sms', {
                method: 'POST',
                body: JSON.stringify({
                    phone_number: phoneNumber,
                    redirect_url: window.location.href
                })
            });

            hideLoading(smsPasswordlessForm);

            // Show OTP input form
            const formContainer = smsPasswordlessForm.parentElement;
            formContainer.innerHTML = `
        <div class="text-center mb-4">
          <h3>Enter Verification Code</h3>
          <p>We sent a code to ${phoneNumber}</p>
        </div>
        <form id="sms-code-form">
          <div class="otp-input-container">
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
            <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
          </div>
          <input type="hidden" name="phone_number" value="${phoneNumber}">
          <button type="submit" class="btn btn-primary w-100">Verify Code</button>
          <div class="text-center mt-3">
            <button type="button" class="btn btn-link" id="resend-code">Resend Code</button>
          </div>
        </form>
      `;

            // Setup OTP inputs
            setupOTPInputs();

            // Setup SMS code verification
            const smsCodeForm = document.getElementById('sms-code-form');
            if (smsCodeForm) {
                smsCodeForm.addEventListener('submit', (e) => {
                    e.preventDefault();

                    const otpInputs = smsCodeForm.querySelectorAll('.otp-input');
                    const code = Array.from(otpInputs).map(input => input.value).join('');

                    verifySMSCode(phoneNumber, code);
                });
            }

            // Setup resend button
            const resendButton = document.getElementById('resend-code');
            if (resendButton) {
                resendButton.addEventListener('click', () => {
                    resendSMSCode(phoneNumber);
                });
            }

        } catch (error) {
            hideLoading(smsPasswordlessForm);

            if (error.data && error.data.error) {
                showNotification(error.data.error.message || 'Failed to send verification code', 'error');
            } else {
                showNotification('An error occurred. Please try again.', 'error');
            }
        }
    });
}

/**
 * Setup OTP input fields
 */
function setupOTPInputs() {
    const otpInputs = document.querySelectorAll('.otp-input');

    otpInputs.forEach((input, index) => {
        input.addEventListener('keydown', (e) => {
            // Allow tab, backspace, delete, arrow keys
            if (['Tab', 'Backspace', 'Delete', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
                return;
            }

            // Allow numbers only
            if (!/^\d$/.test(e.key)) {
                e.preventDefault();
                return;
            }

            // Clear existing value on key press
            if (input.value) {
                input.value = '';
            }
        });

        input.addEventListener('input', () => {
            // Move to next input after filling
            if (input.value && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
        });

        input.addEventListener('keyup', (e) => {
            // Handle backspace
            if (e.key === 'Backspace' && !input.value && index > 0) {
                otpInputs[index - 1].focus();
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();

            // Get pasted content
            const pastedText = (e.clipboardData || window.clipboardData).getData('text');
            if (!pastedText) return;

            // Only use numbers from pasted text
            const numbers = pastedText.replace(/\D/g, '');

            // Fill inputs
            for (let i = 0; i < Math.min(numbers.length, otpInputs.length); i++) {
                otpInputs[i].value = numbers[i];
            }

            // Focus on next empty input or last input
            for (let i = 0; i < otpInputs.length; i++) {
                if (!otpInputs[i].value) {
                    otpInputs[i].focus();
                    break;
                }

                if (i === otpInputs.length - 1) {
                    otpInputs[i].focus();
                }
            }
        });
    });

    // Focus on first input
    if (otpInputs.length) {
        otpInputs[0].focus();
    }
}

/**
 * Verify SMS code
 * @param {string} phoneNumber - The phone number
 * @param {string} code - The verification code
 */
async function verifySMSCode(phoneNumber, code) {
    const form = document.getElementById('sms-code-form');
    if (!form) return;

    try {
        showLoading(form);

        const response = await apiRequest('/api/v1/auth/passwordless/verify', {
            method: 'POST',
            body: JSON.stringify({
                phone_number: phoneNumber,
                code,
                auth_type: 'sms'
            })
        });

        // Redirect to dashboard or specified redirect_url
        const urlParams = new URLSearchParams(window.location.search);
        const redirectUrl = urlParams.get('redirect_url') || '/dashboard';
        window.location.href = redirectUrl;

    } catch (error) {
        hideLoading(form);

        if (error.data && error.data.error) {
            showNotification(error.data.error.message || 'Invalid verification code', 'error');
        } else {
            showNotification('An error occurred. Please try again.', 'error');
        }
    }
}

/**
 * Resend SMS code
 * @param {string} phoneNumber - The phone number
 */
async function resendSMSCode(phoneNumber) {
    try {
        const response = await apiRequest('/api/v1/auth/passwordless/sms', {
            method: 'POST',
            body: JSON.stringify({
                phone_number: phoneNumber,
                redirect_url: window.location.href
            })
        });

        showNotification('Verification code sent successfully', 'success');

    } catch (error) {
        if (error.data && error.data.error) {
            showNotification(error.data.error.message || 'Failed to send verification code', 'error');
        } else {
            showNotification('An error occurred. Please try again.', 'error');
        }
    }
}

/**
 * Initialize MFA components
 */
function initMFAComponents() {
    // TOTP setup
    initTOTPSetup();

    // TOTP verification
    initTOTPVerification();

    // MFA methods selection
    initMFAMethodsSelection();
}

/**
 * Initialize TOTP setup
 */
function initTOTPSetup() {
    const totpSetupForm = document.getElementById('totp-setup-form');
    if (!totpSetupForm) return;

    totpSetupForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(totpSetupForm)) {
            return;
        }

        const formData = new FormData(totpSetupForm);
        const code = formData.get('code');

        try {
            showLoading(totpSetupForm);

            const response = await apiRequest('/api/v1/auth/mfa/verify', {
                method: 'POST',
                body: JSON.stringify({
                    method: 'totp',
                    code
                })
            });

            hideLoading(totpSetupForm);

            showNotification('TOTP setup successful', 'success');

            // Redirect to MFA settings page
            setTimeout(() => {
                window.location.href = '/settings/security';
            }, 1500);

        } catch (error) {
            hideLoading(totpSetupForm);

            if (error.data && error.data.error) {
                showNotification(error.data.error.message || 'Invalid verification code', 'error');
            } else {
                showNotification('An error occurred. Please try again.', 'error');
            }
        }
    });
}

/**
 * Initialize TOTP verification
 */
function initTOTPVerification() {
    const totpVerificationForm = document.getElementById('totp-verification-form');
    if (!totpVerificationForm) return;

    totpVerificationForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(totpVerificationForm)) {
            return;
        }

        const formData = new FormData(totpVerificationForm);
        const code = formData.get('code');

        try {
            showLoading(totpVerificationForm);

            const response = await apiRequest('/api/v1/auth/mfa/verify', {
                method: 'POST',
                body: JSON.stringify({
                    method: 'totp',
                    code
                })
            });

            // Redirect to dashboard or specified redirect_url
            const urlParams = new URLSearchParams(window.location.search);
            const redirectUrl = urlParams.get('redirect_url') || '/dashboard';
            window.location.href = redirectUrl;

        } catch (error) {
            hideLoading(totpVerificationForm);

            if (error.data && error.data.error) {
                showNotification(error.data.error.message || 'Invalid verification code', 'error');
            } else {
                showNotification('An error occurred. Please try again.', 'error');
            }
        }
    });
}

/**
 * Initialize MFA methods selection
 */
function initMFAMethodsSelection() {
    const mfaMethodsContainer = document.getElementById('mfa-methods');
    if (!mfaMethodsContainer) return;

    const mfaOptions = mfaMethodsContainer.querySelectorAll('.mfa-option');

    mfaOptions.forEach(option => {
        option.addEventListener('click', () => {
            const method = option.getAttribute('data-method');

            // Remove active class from all options
            mfaOptions.forEach(opt => opt.classList.remove('active'));

            // Add active class to selected option
            option.classList.add('active');

            // Show corresponding method form
            const methodForms = document.querySelectorAll('.mfa-method-form');
            methodForms.forEach(form => {
                form.style.display = 'none';
            });

            const selectedForm = document.getElementById(`mfa-${method}-form`);
            if (selectedForm) {
                selectedForm.style.display = 'block';
            }
        });
    });
}

/**
 * Initialize password reset functionality
 */
function initPasswordReset() {
    // Forgot password form
    initForgotPasswordForm();

    // Reset password form
    initResetPasswordForm();
}

/**
 * Initialize forgot password form
 */
function initForgotPasswordForm() {
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    if (!forgotPasswordForm) return;

    forgotPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(forgotPasswordForm)) {
            return;
        }

        const formData = new FormData(forgotPasswordForm);
        const email = formData.get('email');

        try {
            showLoading(forgotPasswordForm);

            const response = await apiRequest('/api/v1/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({
                    email,
                    redirect_url: window.location.origin + '/reset-password'
                })
            });

            hideLoading(forgotPasswordForm);

            // Show success message
            const formContainer = forgotPasswordForm.parentElement;
            formContainer.innerHTML = `
        <div class="text-center">
          <h3>Check Your Email</h3>
          <p>We've sent password reset instructions to:</p>
          <div class="mt-2 mb-2"><strong>${email}</strong></div>
          <p>Click the link in the email to reset your password.</p>
          <div class="mt-4">
            <a href="/login" class="btn btn-outline">Back to Login</a>
          </div>
        </div>
      `;

        } catch (error) {
            hideLoading(forgotPasswordForm);

            // Always show success even if email doesn't exist (for security)
            const formContainer = forgotPasswordForm.parentElement;
            formContainer.innerHTML = `
        <div class="text-center">
          <h3>Check Your Email</h3>
          <p>If an account exists for ${email}, we've sent password reset instructions.</p>
          <div class="mt-4">
            <a href="/login" class="btn btn-outline">Back to Login</a>
          </div>
        </div>
      `;
        }
    });
}

/**
 * Initialize reset password form
 */
function initResetPasswordForm() {
    const resetPasswordForm = document.getElementById('reset-password-form');
    if (!resetPasswordForm) return;

    resetPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!validateForm(resetPasswordForm)) {
            return;
        }

        const formData = new FormData(resetPasswordForm);
        const token = formData.get('token');
        const newPassword = formData.get('new_password');

        try {
            showLoading(resetPasswordForm);

            const response = await apiRequest('/api/v1/auth/reset-password', {
                method: 'POST',
                body: JSON.stringify({
                    token,
                    new_password: newPassword
                })
            });

            hideLoading(resetPasswordForm);

            // Show success message
            const formContainer = resetPasswordForm.parentElement;
            formContainer.innerHTML = `
        <div class="text-center">
          <h3>Password Reset Successful</h3>
          <p>Your password has been reset successfully.</p>
          <div class="mt-4">
            <a href="/login" class="btn btn-primary">Login with New Password</a>
          </div>
        </div>
      `;

        } catch (error) {
            hideLoading(resetPasswordForm);

            if (error.data && error.data.error) {
                showNotification(error.data.error.message || 'Password reset failed', 'error');
            } else {
                showNotification('An error occurred. Please try again.', 'error');
            }
        }
    });
}

/**
 * Initialize organization selector
 */
function initOrganizationSelector() {
    const organizationSelector = document.getElementById('organization-selector');
    if (!organizationSelector) return;

    organizationSelector.addEventListener('change', () => {
        const organizationId = organizationSelector.value;

        // Store selected organization in local storage
        if (organizationId) {
            localStorage.setItem('selected_organization', organizationId);
        } else {
            localStorage.removeItem('selected_organization');
        }

        // Refresh the page to apply organization context
        window.location.reload();
    });

    // Set initial value from local storage
    const storedOrganization = localStorage.getItem('selected_organization');
    if (storedOrganization) {
        organizationSelector.value = storedOrganization;
    }
}