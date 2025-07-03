import type {Preview} from '@storybook/react';
import type * as React from 'react';
import {HeroUIProvider} from '@heroui/react';
import {action} from '@storybook/addon-actions';

// Import global styles
import '../src/styles/globals.css';

// Mock implementations for Frank Auth hooks and providers
const MockFrankAuthProvider = ({ children }: { children: React.ReactNode }) => {
    return (
        <div data-testid="mock-frank-auth-provider">
            {children}
        </div>
    );
};

// Default configuration values for stories
const defaultConfig = {
    publishableKey: 'pk_test_storybook',
    userType: 'external' as const,
    apiUrl: 'https://api.frankauth.dev',
    theme: {
        mode: 'light' as const,
        colors: {
            primary: '#3b82f6',
            secondary: '#64748b',
        },
    },
    appearance: {
        layout: {
            centered: true,
            maxWidth: 'md' as const,
        },
        components: {
            card: {
                variant: 'shadow' as const,
                size: 'md' as const,
            },
        },
    },
};

// Mock handlers for authentication actions
const mockHandlers = {
    onSignIn: action('onSignIn'),
    onSignUp: action('onSignUp'),
    onSignOut: action('onSignOut'),
    onPasswordReset: action('onPasswordReset'),
    onVerifyEmail: action('onVerifyEmail'),
    onVerifyPhone: action('onVerifyPhone'),
    onMagicLink: action('onMagicLink'),
    onOAuth: action('onOAuth'),
    onMFASetup: action('onMFASetup'),
    onError: action('onError'),
    onSuccess: action('onSuccess'),
};

const preview: Preview = {
    parameters: {
        actions: { argTypesRegex: '^on[A-Z].*' },
        controls: {
            matchers: {
                color: /(background|color)$/i,
                date: /Date$/,
            },
            expanded: true,
        },
        docs: {
            story: {
                inline: true,
            },
            canvas: {
                sourceState: 'shown',
            },
        },
        backgrounds: {
            default: 'light',
            values: [
                {
                    name: 'light',
                    value: '#ffffff',
                },
                {
                    name: 'dark',
                    value: '#000000',
                },
                {
                    name: 'gray',
                    value: '#f8fafc',
                },
            ],
        },
        viewport: {
            viewports: {
                mobile: {
                    name: 'Mobile',
                    styles: {
                        width: '375px',
                        height: '667px',
                    },
                },
                tablet: {
                    name: 'Tablet',
                    styles: {
                        width: '768px',
                        height: '1024px',
                    },
                },
                desktop: {
                    name: 'Desktop',
                    styles: {
                        width: '1200px',
                        height: '800px',
                    },
                },
            },
        },
        layout: 'centered',
    },

    globalTypes: {
        theme: {
            description: 'Global theme for components',
            defaultValue: 'light',
            toolbar: {
                title: 'Theme',
                icon: 'paintbrush',
                items: [
                    { value: 'light', title: 'Light', left: '☀️' },
                    { value: 'dark', title: 'Dark', left: '🌙' },
                ],
                dynamicTitle: true,
            },
        },
        organizationType: {
            description: 'Organization type for theming',
            defaultValue: 'standard',
            toolbar: {
                title: 'Organization',
                icon: 'component',
                items: [
                    { value: 'standard', title: 'Standard Org' },
                    { value: 'enterprise', title: 'Enterprise Org' },
                    { value: 'custom', title: 'Custom Branded' },
                ],
                dynamicTitle: true,
            },
        },
        userType: {
            description: 'User type for authentication flows',
            defaultValue: 'external',
            toolbar: {
                title: 'User Type',
                icon: 'user',
                items: [
                    { value: 'internal', title: 'Internal User' },
                    { value: 'external', title: 'External User' },
                    { value: 'end', title: 'End User' },
                ],
                dynamicTitle: true,
            },
        },
    },

    decorators: [
        (Story, context) => {
            const { theme, organizationType, userType } = context.globals;

            // Organization configurations for different types
            const organizationConfigs = {
                standard: {
                    name: 'Acme Corp',
                    branding: {
                        logo: 'https://via.placeholder.com/150x50/3b82f6/ffffff?text=ACME',
                        primaryColor: '#3b82f6',
                        secondaryColor: '#64748b',
                    },
                },
                enterprise: {
                    name: 'Enterprise Solutions Inc',
                    branding: {
                        logo: 'https://via.placeholder.com/150x50/059669/ffffff?text=ENTERPRISE',
                        primaryColor: '#059669',
                        secondaryColor: '#374151',
                        customCSS: `
              .frank-auth-card { 
                border-left: 4px solid #059669; 
              }
            `,
                    },
                },
                custom: {
                    name: 'Custom Brand Co',
                    branding: {
                        logo: 'https://via.placeholder.com/150x50/dc2626/ffffff?text=CUSTOM',
                        primaryColor: '#dc2626',
                        secondaryColor: '#991b1b',
                        customCSS: `
              .frank-auth-card { 
                background: linear-gradient(135deg, #fee2e2 0%, #ffffff 100%);
                border: 2px solid #dc2626;
              }
            `,
                    },
                },
            };

            const config = {
                ...defaultConfig,
                userType,
                theme: {
                    ...defaultConfig.theme,
                    mode: theme,
                },
                organization: organizationConfigs[organizationType as keyof typeof organizationConfigs],
            };

            return (
                <HeroUIProvider>
                    <MockFrankAuthProvider>
                        <div
                            className={`min-h-screen transition-colors duration-200 ${
                                theme === 'dark'
                                    ? 'dark bg-black text-white'
                                    : 'bg-gray-50 text-gray-900'
                            }`}
                            data-theme={theme}
                            data-organization-type={organizationType}
                            data-user-type={userType}
                        >
                            <div className="p-4">
                                <Story
                                    args={{
                                        ...context.args,
                                        ...mockHandlers,
                                        config,
                                    }}
                                />
                            </div>
                        </div>
                    </MockFrankAuthProvider>
                </HeroUIProvider>
            );
        },
    ],

    argTypes: {
        // Common arg types for all stories
        className: {
            control: 'text',
            description: 'Additional CSS classes',
        },
        disabled: {
            control: 'boolean',
            description: 'Whether the component is disabled',
        },
        loading: {
            control: 'boolean',
            description: 'Loading state',
        },
        error: {
            control: 'text',
            description: 'Error message to display',
        },
        // Event handlers
        onSuccess: { action: 'success' },
        onError: { action: 'error' },
        onSubmit: { action: 'submit' },
        onChange: { action: 'change' },
        onFocus: { action: 'focus' },
        onBlur: { action: 'blur' },
    },
};

export default preview;