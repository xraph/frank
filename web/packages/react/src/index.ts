// packages/react/src/index.ts
/**
 * @frank-auth/react - Main Entry Point
 *
 * A comprehensive, highly configurable React authentication UI library
 * Built for the Frank Auth multi-tenant SaaS platform
 *
 * Features:
 * - Three-tier user system support (Internal, External, End Users)
 * - Complete server-driven configuration
 * - Highly customizable components and themes
 * - Multi-factor authentication (MFA)
 * - Passkey support (WebAuthn)
 * - Social authentication (OAuth)
 * - Organization management
 * - Session management
 * - Real-time features
 * - Accessibility compliant (WCAG 2.1 AA)
 * - Internationalization (i18n)
 * - TypeScript support
 */

// =============================================================================
// MAIN PROVIDER
// =============================================================================
export * from './provider';

// =============================================================================
// CORE AUTHENTICATION COMPONENTS
// =============================================================================

// // Sign In Components
// export { SignIn } from './components/auth/sign-in/sign-in';
// export { SignInForm } from './components/auth/sign-in/sign-in-form';
// export { SignInModal } from './components/auth/sign-in/sign-in-modal';
// export { SignInButton } from './components/auth/sign-in/sign-in-button';
// export { SignInCard } from './components/auth/sign-in/sign-in-card';
//
// // Sign Up Components
// export { SignUp } from './components/auth/sign-up/sign-up';
// export { SignUpForm } from './components/auth/sign-up/sign-up-form';
// export { SignUpModal } from './components/auth/sign-up/sign-up-modal';
// export { SignUpButton } from './components/auth/sign-up/sign-up-button';
// export { SignUpCard } from './components/auth/sign-up/sign-up-card';
//
// // User Components
// export { UserButton } from './components/auth/user-button/user-button';
// export { UserProfile } from './components/auth/user-button/user-profile';
// export { UserAvatar } from './components/auth/user-button/user-avatar';

// User Profile Management
import './styles/global.css'

export * from './components';
export * from './types/user';
export * from './types/session';

// // =============================================================================
// // DEVELOPMENT EXPORTS (Only in development)
// // =============================================================================
//
// if (process.env.NODE_ENV === 'development') {
//     // Export internal utilities for testing
//     (window as any).__FRANK_AUTH__ = {
//         VERSION,
//         PRESET_CONFIGS,
//         // Add development-only utilities
//     };
// }