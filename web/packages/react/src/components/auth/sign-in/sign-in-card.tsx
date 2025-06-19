/**
 * @frank-auth/react - Sign In Card Component
 *
 * Card wrapper for sign-in form with customizable styling and layout.
 */

'use client';

import React from 'react';
import {Card, CardBody, CardFooter, CardHeader, Divider} from '@heroui/react';
import {motion} from 'framer-motion';

import {SignInForm} from './sign-in-form';
import {useConfig} from '../../../hooks/use-config';
import {useTheme} from '../../../hooks/use-theme';

// ============================================================================
// Sign In Card Types
// ============================================================================

export interface SignInCardProps {
    /**
     * Card variant
     */
    variant?: 'shadow' | 'bordered' | 'flat';

    /**
     * Custom className
     */
    className?: string;

    /**
     * Card padding
     */
    padding?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Card radius
     */
    radius?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Whether card has shadow
     */
    shadow?: 'none' | 'sm' | 'md' | 'lg';

    /**
     * Whether card is blurred
     */
    isBlurred?: boolean;

    /**
     * Sign-in methods to show
     */
    methods?: ('password' | 'oauth' | 'magic-link' | 'passkey' | 'sso')[];

    /**
     * Initial email value
     */
    email?: string;

    /**
     * Initial organization ID
     */
    organizationId?: string;

    /**
     * Redirect URL after successful sign-in
     */
    redirectUrl?: string;

    /**
     * Success callback
     */
    onSuccess?: (result: any) => void;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Custom title
     */
    title?: string;

    /**
     * Custom subtitle
     */
    subtitle?: string;

    /**
     * Form size
     */
    size?: 'sm' | 'md' | 'lg';

    /**
     * Whether to show branding
     */
    showBranding?: boolean;

    /**
     * Disabled state
     */
    disabled?: boolean;

    /**
     * Custom footer content
     */
    footer?: React.ReactNode;

    /**
     * Custom header content
     */
    header?: React.ReactNode;

    /**
     * Card background image
     */
    backgroundImage?: string;

    /**
     * Card background gradient
     */
    backgroundGradient?: string;

    /**
     * Animation on mount
     */
    animated?: boolean;

    /**
     * Card max width
     */
    maxWidth?: string | number;

    /**
     * Center the card
     */
    centered?: boolean;

    /**
     * Full height card
     */
    fullHeight?: boolean;

    /**
     * Show organization branding
     */
    showOrganizationBranding?: boolean;

    /**
     * Custom card header
     */
    cardHeader?: React.ReactNode;

    /**
     * Custom card footer
     */
    cardFooter?: React.ReactNode;

    /**
     * Hide card header
     */
    hideCardHeader?: boolean;

    /**
     * Hide card footer
     */
    hideCardFooter?: boolean;
}

// ============================================================================
// Sign In Card Component
// ============================================================================

export function SignInCard({
                               variant = 'shadow',
                               className = '',
                               padding = 'lg',
                               radius = 'lg',
                               shadow = 'md',
                               isBlurred = false,
                               methods = ['password', 'oauth', 'magic-link'],
                               email,
                               organizationId,
                               redirectUrl,
                               onSuccess,
                               onError,
                               title,
                               subtitle,
                               size = 'md',
                               showBranding = true,
                               disabled = false,
                               footer,
                               header,
                               backgroundImage,
                               backgroundGradient,
                               animated = true,
                               maxWidth = 400,
                               centered = false,
                               fullHeight = false,
                               showOrganizationBranding = true,
                               cardHeader,
                               cardFooter,
                               hideCardHeader = false,
                               hideCardFooter = false,
                           }: SignInCardProps) {
    const { components, organizationSettings } = useConfig();
    const { getColorValue } = useTheme();

    // Custom component override
    const CustomSignInCard = components.SignInCard;
    if (CustomSignInCard) {
        return <CustomSignInCard {...{
            variant, className, padding, radius, shadow, isBlurred, methods,
            email, organizationId, redirectUrl, onSuccess, onError, title,
            subtitle, size, showBranding, disabled, footer, header,
            backgroundImage, backgroundGradient, animated, maxWidth, centered,
            fullHeight, showOrganizationBranding, cardHeader, cardFooter,
            hideCardHeader, hideCardFooter
        }} />;
    }

    // Animation variants
    const cardVariants = {
        hidden: {
            opacity: 0,
            y: 20,
            scale: 0.95
        },
        visible: {
            opacity: 1,
            y: 0,
            scale: 1,
            transition: {
                duration: 0.3,
                ease: 'easeOut'
            }
        }
    };

    // Card styles
    const cardStyles: React.CSSProperties = {};

    if (backgroundImage) {
        cardStyles.backgroundImage = `url(${backgroundImage})`;
        cardStyles.backgroundSize = 'cover';
        cardStyles.backgroundPosition = 'center';
    }

    if (backgroundGradient) {
        cardStyles.background = backgroundGradient;
    }

    if (maxWidth) {
        cardStyles.maxWidth = typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth;
    }

    // Organization branding
    const orgBranding = showOrganizationBranding && organizationSettings?.branding;

    // Container classes
    const containerClasses = [
        centered ? 'flex items-center justify-center min-h-screen p-4' : '',
        fullHeight ? 'h-full' : '',
    ].filter(Boolean).join(' ');

    // Card component
    const cardContent = (
        <Card
            className={`${className} ${centered ? 'w-full' : ''}`}
            style={cardStyles}
            shadow={shadow}
            radius={radius}
            isBlurred={isBlurred}
        >
            {/* Card Header */}
            {!hideCardHeader && (cardHeader || title || subtitle || orgBranding) && (
                <CardHeader className={`flex flex-col items-center text-center gap-2 p-${padding}`}>
                    {cardHeader || (
                        <>
                            {/* Organization Logo */}
                            {orgBranding?.logoUrl && (
                                <img
                                    src={orgBranding.logoUrl}
                                    alt="Organization Logo"
                                    className="h-12 w-auto mb-2"
                                />
                            )}

                            {/* Title */}
                            {title && (
                                <h1 className="text-2xl font-bold text-foreground">
                                    {title}
                                </h1>
                            )}

                            {/* Subtitle */}
                            {subtitle && (
                                <p className="text-default-500 text-sm max-w-sm">
                                    {subtitle}
                                </p>
                            )}

                            {/* Custom Header */}
                            {header}
                        </>
                    )}
                </CardHeader>
            )}

            {/* Divider */}
            {!hideCardHeader && (cardHeader || title || subtitle || orgBranding) && !hideCardFooter && (
                <Divider />
            )}

            {/* Card Body */}
            <CardBody className={`p-${padding}`}>
                <SignInForm
                    methods={methods}
                    email={email}
                    organizationId={organizationId}
                    redirectUrl={redirectUrl}
                    onSuccess={onSuccess}
                    onError={onError}
                    title={hideCardHeader ? title : undefined}
                    subtitle={hideCardHeader ? subtitle : undefined}
                    size={size}
                    showBranding={hideCardHeader ? showBranding : false}
                    disabled={disabled}
                    variant="minimal"
                    className="space-y-4"
                />
            </CardBody>

            {/* Card Footer */}
            {!hideCardFooter && (cardFooter || footer) && (
                <>
                    <Divider />
                    <CardFooter className={`p-${padding} text-center`}>
                        {cardFooter || footer}
                    </CardFooter>
                </>
            )}
        </Card>
    );

    // Wrap with animation if enabled
    const animatedCard = animated ? (
        <motion.div
            initial="hidden"
            animate="visible"
            variants={cardVariants}
            style={{ maxWidth }}
            className={centered ? 'w-full' : ''}
        >
            {cardContent}
        </motion.div>
    ) : (
        <div style={{ maxWidth }} className={centered ? 'w-full' : ''}>
            {cardContent}
        </div>
    );

    // Wrap with container if centered
    return centered ? (
        <div className={containerClasses}>
            {animatedCard}
        </div>
    ) : animatedCard;
}

// ============================================================================
// Sign In Card Variants
// ============================================================================

/**
 * Bordered Sign In Card
 */
export function BorderedSignInCard(props: Omit<SignInCardProps, 'variant'>) {
    return (
        <SignInCard
            {...props}
            variant="bordered"
        />
    );
}

/**
 * Flat Sign In Card
 */
export function FlatSignInCard(props: Omit<SignInCardProps, 'variant'>) {
    return (
        <SignInCard
            {...props}
            variant="flat"
        />
    );
}

/**
 * Compact Sign In Card
 */
export function CompactSignInCard(props: SignInCardProps) {
    return (
        <SignInCard
            {...props}
            padding="sm"
            size="sm"
            maxWidth={320}
        />
    );
}

/**
 * Large Sign In Card
 */
export function LargeSignInCard(props: SignInCardProps) {
    return (
        <SignInCard
            {...props}
            padding="lg"
            size="lg"
            maxWidth={500}
        />
    );
}

/**
 * Centered Sign In Card (for full-page layouts)
 */
export function CenteredSignInCard(props: Omit<SignInCardProps, 'centered'>) {
    return (
        <SignInCard
            {...props}
            centered
        />
    );
}

/**
 * Blurred Glass Sign In Card
 */
export function GlassSignInCard(props: SignInCardProps) {
    return (
        <SignInCard
            {...props}
            variant="shadow"
            isBlurred
            backgroundGradient="rgba(255, 255, 255, 0.1)"
            className="backdrop-blur-md border border-white/20"
        />
    );
}

/**
 * Gradient Sign In Card
 */
export function GradientSignInCard({
                                       backgroundGradient = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                                       ...props
                                   }: SignInCardProps) {
    return (
        <SignInCard
            {...props}
            variant="shadow"
            backgroundGradient={backgroundGradient}
            className="text-white"
        />
    );
}

/**
 * Minimal Sign In Card
 */
export function MinimalSignInCard(props: SignInCardProps) {
    return (
        <SignInCard
            {...props}
            variant="flat"
            shadow="none"
            padding="md"
            hideCardHeader
            hideCardFooter
        />
    );
}

// ============================================================================
// Branded Sign In Card
// ============================================================================

export interface BrandedSignInCardProps extends SignInCardProps {
    /**
     * Brand logo URL
     */
    logo?: string;

    /**
     * Brand name
     */
    brandName?: string;

    /**
     * Brand colors
     */
    brandColors?: {
        primary?: string;
        secondary?: string;
        accent?: string;
    };

    /**
     * Brand fonts
     */
    brandFonts?: {
        heading?: string;
        body?: string;
    };
}

export function BrandedSignInCard({
                                      logo,
                                      brandName,
                                      brandColors,
                                      brandFonts,
                                      title,
                                      subtitle,
                                      className = '',
                                      cardHeader,
                                      ...props
                                  }: BrandedSignInCardProps) {
    const customHeader = cardHeader || (
        <div className="flex flex-col items-center gap-4">
            {logo && (
                <img
                    src={logo}
                    alt={`${brandName} Logo`}
                    className="h-16 w-auto"
                />
            )}

            {title && (
                <h1
                    className="text-3xl font-bold"
                    style={{
                        color: brandColors?.primary,
                        fontFamily: brandFonts?.heading
                    }}
                >
                    {title}
                </h1>
            )}

            {subtitle && (
                <p
                    className="text-default-500 max-w-sm text-center"
                    style={{ fontFamily: brandFonts?.body }}
                >
                    {subtitle}
                </p>
            )}
        </div>
    );

    return (
        <SignInCard
            {...props}
            title={undefined} // Override since we handle in custom header
            subtitle={undefined}
            cardHeader={customHeader}
            className={`${className} branded-card`}
            style={{
                '--brand-primary': brandColors?.primary,
                '--brand-secondary': brandColors?.secondary,
                '--brand-accent': brandColors?.accent,
            } as React.CSSProperties}
        />
    );
}

// ============================================================================
// Organization-themed Sign In Card
// ============================================================================

export function OrganizationSignInCard(props: SignInCardProps) {
    const { organizationSettings } = useConfig();

    if (!organizationSettings) {
        return <SignInCard {...props} />;
    }

    const branding = organizationSettings.branding;

    return (
        <BrandedSignInCard
            {...props}
            logo={branding?.logoUrl}
            brandName={organizationSettings.name}
            brandColors={{
                primary: branding?.primaryColor,
                secondary: branding?.secondaryColor,
            }}
            backgroundGradient={branding?.primaryColor ?
                `linear-gradient(135deg, ${branding.primaryColor}20 0%, ${branding.secondaryColor || branding.primaryColor}20 100%)` :
                undefined
            }
        />
    );
}

// ============================================================================
// Export
// ============================================================================

export default SignInCard;