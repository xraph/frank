// Localization Types

// Supported locales
export type Locale =
    | 'en'  // English
    | 'es'  // Spanish
    | 'fr'  // French
    | 'de'  // German
    | 'pt'  // Portuguese
    | 'it'  // Italian
    | 'ja'  // Japanese
    | 'ko'  // Korean
    | 'zh'; // Chinese

// Locale direction
export type LocaleDirection = 'ltr' | 'rtl';

// Main locale messages structure
export interface LocaleMessages {
    // Common UI elements
    common: {
        // Actions
        actions: {
            save: string;
            cancel: string;
            delete: string;
            edit: string;
            update: string;
            create: string;
            submit: string;
            reset: string;
            clear: string;
            search: string;
            filter: string;
            sort: string;
            refresh: string;
            reload: string;
            back: string;
            next: string;
            previous: string;
            continue: string;
            finish: string;
            close: string;
            open: string;
            show: string;
            hide: string;
            copy: string;
            paste: string;
            cut: string;
            select: string;
            selectAll: string;
            deselect: string;
            confirm: string;
            deny: string;
            approve: string;
            reject: string;
            retry: string;
            undo: string;
            redo: string;
        };

        // Status
        status: {
            loading: string;
            success: string;
            error: string;
            warning: string;
            info: string;
            pending: string;
            completed: string;
            failed: string;
            cancelled: string;
            active: string;
            inactive: string;
            enabled: string;
            disabled: string;
            online: string;
            offline: string;
            connected: string;
            disconnected: string;
        };

        // Time-related
        timeAgo: {
            justNow: string;
            minutesAgo: string;
            hoursAgo: string;
            daysAgo: string;
            weeksAgo: string;
            monthsAgo: string;
            yearsAgo: string;
        };

        // Navigation
        navigation: {
            home: string;
            dashboard: string;
            profile: string;
            settings: string;
            help: string;
            support: string;
            documentation: string;
            feedback: string;
            about: string;
            privacy: string;
            terms: string;
            contact: string;
        };

        // General
        general: {
            yes: string;
            no: string;
            ok: string;
            maybe: string;
            none: string;
            all: string;
            other: string;
            unknown: string;
            optional: string;
            required: string;
            recommended: string;
            advanced: string;
            basic: string;
            custom: string;
            default: string;
            example: string;
            placeholder: string;
            noData: string;
            noResults: string;
            empty: string;
            total: string;
            subtotal: string;
            count: string;
            limit: string;
            unlimited: string;
        };
    };

    // Authentication messages
    auth: {
        // Sign in
        signIn: {
            title: string;
            subtitle: string;
            emailLabel: string;
            emailPlaceholder: string;
            usernameLabel: string;
            usernamePlaceholder: string;
            passwordLabel: string;
            passwordPlaceholder: string;
            rememberMe: string;
            forgotPassword: string;
            signInButton: string;
            signInWithProvider: string;
            orDivider: string;
            noAccount: string;
            createAccount: string;
            success: string;
            welcomeBack: string;
        };

        // Sign up
        signUp: {
            title: string;
            subtitle: string;
            firstNameLabel: string;
            firstNamePlaceholder: string;
            lastNameLabel: string;
            lastNamePlaceholder: string;
            emailLabel: string;
            emailPlaceholder: string;
            usernameLabel: string;
            usernamePlaceholder: string;
            passwordLabel: string;
            passwordPlaceholder: string;
            confirmPasswordLabel: string;
            confirmPasswordPlaceholder: string;
            phoneLabel: string;
            phonePlaceholder: string;
            signUpButton: string;
            signUpWithProvider: string;
            orDivider: string;
            hasAccount: string;
            signInLink: string;
            termsAcceptance: string;
            termsOfService: string;
            privacyPolicy: string;
            success: string;
            welcomeMessage: string;
        };

        // Password reset
        passwordReset: {
            title: string;
            subtitle: string;
            emailLabel: string;
            emailPlaceholder: string;
            sendResetButton: string;
            backToSignIn: string;
            success: string;
            checkEmail: string;
            resetPassword: string;
            newPasswordLabel: string;
            newPasswordPlaceholder: string;
            confirmNewPasswordLabel: string;
            confirmNewPasswordPlaceholder: string;
            resetButton: string;
            passwordUpdated: string;
        };

        // Multi-factor authentication
        mfa: {
            title: string;
            subtitle: string;
            codeLabel: string;
            codePlaceholder: string;
            verifyButton: string;
            resendCode: string;
            useBackupCode: string;
            backupCodeLabel: string;
            backupCodePlaceholder: string;
            useAuthenticator: string;
            success: string;
            setup: {
                title: string;
                subtitle: string;
                step1: string;
                step2: string;
                step3: string;
                downloadApp: string;
                scanQR: string;
                enterCode: string;
                manualEntry: string;
                secretKey: string;
                verificationCode: string;
                enableButton: string;
                backupCodes: string;
                saveBackupCodes: string;
                backupCodesWarning: string;
            };
        };

        // Passkeys
        passkeys: {
            title: string;
            subtitle: string;
            setup: string;
            use: string;
            notSupported: string;
            setupButton: string;
            useButton: string;
            success: string;
            registered: string;
            manage: {
                title: string;
                noPasskeys: string;
                addPasskey: string;
                deviceName: string;
                createdAt: string;
                lastUsed: string;
                remove: string;
                removeConfirm: string;
            };
        };

        // OAuth
        oauth: {
            signInWith: string;
            signUpWith: string;
            continueWith: string;
            connecting: string;
            success: string;
            error: string;
            cancelled: string;
            providers: {
                google: string;
                github: string;
                microsoft: string;
                facebook: string;
                apple: string;
                twitter: string;
                linkedin: string;
                discord: string;
                slack: string;
                spotify: string;
            };
        };

        // Email verification
        verification: {
            email: {
                title: string;
                subtitle: string;
                checkEmail: string;
                resendEmail: string;
                changeEmail: string;
                success: string;
                verified: string;
            };
            phone: {
                title: string;
                subtitle: string;
                codeLabel: string;
                codePlaceholder: string;
                resendCode: string;
                verifyButton: string;
                success: string;
                verified: string;
            };
        };

        // Magic link
        magicLink: {
            title: string;
            subtitle: string;
            emailLabel: string;
            emailPlaceholder: string;
            sendLinkButton: string;
            checkEmail: string;
            success: string;
            expired: string;
            invalid: string;
        };

        // Logout
        logout: {
            title: string;
            subtitle: string;
            button: string;
            confirm: string;
            success: string;
            goodbye: string;
        };

        // Session
        session: {
            expired: string;
            invalid: string;
            refresh: string;
            refreshing: string;
            multipleWarning: string;
            deviceLimit: string;
        };
    };

    // User profile messages
    user: {
        profile: {
            title: string;
            personalInfo: string;
            accountInfo: string;
            security: string;
            preferences: string;
            firstName: string;
            lastName: string;
            email: string;
            username: string;
            phone: string;
            bio: string;
            website: string;
            location: string;
            timezone: string;
            language: string;
            avatar: string;
            changeAvatar: string;
            removeAvatar: string;
            updateProfile: string;
            profileUpdated: string;
        };

        // Security settings
        security: {
            title: string;
            changePassword: string;
            currentPassword: string;
            newPassword: string;
            confirmPassword: string;
            passwordStrength: string;
            passwordRequirements: string;
            twoFactor: string;
            enableTwoFactor: string;
            disableTwoFactor: string;
            twoFactorEnabled: string;
            twoFactorDisabled: string;
            backupCodes: string;
            viewBackupCodes: string;
            regenerateBackupCodes: string;
            devices: string;
            trustedDevices: string;
            removeDevice: string;
            deviceRemoved: string;
            sessions: string;
            activeSessions: string;
            terminateSession: string;
            terminateAllSessions: string;
            sessionTerminated: string;
            connectedAccounts: string;
            disconnect: string;
            accountDisconnected: string;
            deleteAccount: string;
            deleteAccountWarning: string;
            deleteAccountConfirm: string;
            accountDeleted: string;
        };

        // Preferences
        preferences: {
            title: string;
            theme: string;
            lightMode: string;
            darkMode: string;
            systemMode: string;
            notifications: string;
            emailNotifications: string;
            pushNotifications: string;
            smsNotifications: string;
            marketingEmails: string;
            securityAlerts: string;
            accountActivity: string;
            productUpdates: string;
            preferences: string;
            preferencesUpdated: string;
        };
    };

    // Organization messages
    organization: {
        // General
        general: {
            title: string;
            name: string;
            description: string;
            website: string;
            logo: string;
            settings: string;
            members: string;
            billing: string;
            usage: string;
            security: string;
            integrations: string;
            audit: string;
            support: string;
        };

        // Profile
        profile: {
            title: string;
            updateOrganization: string;
            organizationUpdated: string;
            logo: string;
            changeLogo: string;
            removeLogo: string;
            brandColors: string;
            primaryColor: string;
            secondaryColor: string;
            customBranding: string;
            domain: string;
            customDomain: string;
            verifyDomain: string;
            domainVerified: string;
            domainPending: string;
            contact: string;
            contactEmail: string;
            supportUrl: string;
            address: string;
            country: string;
            timezone: string;
        };

        // Members
        members: {
            title: string;
            totalMembers: string;
            activeMembers: string;
            pendingInvitations: string;
            roles: string;
            permissions: string;
            inviteMember: string;
            inviteMembers: string;
            emailAddress: string;
            role: string;
            customMessage: string;
            sendInvitation: string;
            invitationSent: string;
            resendInvitation: string;
            cancelInvitation: string;
            invitationCancelled: string;
            memberName: string;
            memberEmail: string;
            memberRole: string;
            memberStatus: string;
            memberJoined: string;
            lastActive: string;
            changeRole: string;
            removeMember: string;
            removeMemberConfirm: string;
            memberRemoved: string;
            transferOwnership: string;
            transferOwnershipConfirm: string;
            ownershipTransferred: string;
            bulkActions: string;
            selectAll: string;
            selectedMembers: string;
            bulkRemove: string;
            bulkChangeRole: string;
            export: string;
            exportMembers: string;
        };

        // Roles
        roles: {
            title: string;
            createRole: string;
            editRole: string;
            deleteRole: string;
            roleName: string;
            roleDescription: string;
            permissions: string;
            systemPermissions: string;
            organizationPermissions: string;
            memberPermissions: string;
            billingPermissions: string;
            defaultRole: string;
            customRole: string;
            roleCreated: string;
            roleUpdated: string;
            roleDeleted: string;
            assignRole: string;
            unassignRole: string;
            roleAssigned: string;
            roleUnassigned: string;
            owner: string;
            admin: string;
            member: string;
            guest: string;
            viewer: string;
            editor: string;
            manager: string;
        };

        // Settings
        settings: {
            title: string;
            general: string;
            authentication: string;
            security: string;
            integrations: string;
            advanced: string;
            allowPublicSignup: string;
            requireEmailVerification: string;
            allowUsernameSignup: string;
            passwordPolicy: string;
            minPasswordLength: string;
            requireUppercase: string;
            requireLowercase: string;
            requireNumbers: string;
            requireSymbols: string;
            sessionDuration: string;
            mfaRequired: string;
            allowedDomains: string;
            blockedDomains: string;
            ipWhitelist: string;
            ssoEnabled: string;
            ssoProvider: string;
            auditLogRetention: string;
            dataExport: string;
            deleteOrganization: string;
            deleteOrganizationWarning: string;
            deleteOrganizationConfirm: string;
            organizationDeleted: string;
            settingsUpdated: string;
        };

        // Billing
        billing: {
            title: string;
            plan: string;
            currentPlan: string;
            usage: string;
            billing: string;
            invoices: string;
            paymentMethod: string;
            subscription: string;
            seats: string;
            usedSeats: string;
            availableSeats: string;
            addSeats: string;
            removeSeats: string;
            monthlyBilling: string;
            yearlyBilling: string;
            upgrade: string;
            downgrade: string;
            cancel: string;
            pauseSubscription: string;
            resumeSubscription: string;
            billingHistory: string;
            downloadInvoice: string;
            updatePaymentMethod: string;
            paymentMethodUpdated: string;
            subscriptionUpdated: string;
            subscriptionCancelled: string;
            subscriptionPaused: string;
            subscriptionResumed: string;
            trialExpired: string;
            trialDaysLeft: string;
            upgradeNow: string;
        };

        // Invitations
        invitations: {
            title: string;
            youreInvited: string;
            invitedBy: string;
            invitedTo: string;
            roleOffered: string;
            acceptInvitation: string;
            declineInvitation: string;
            invitationAccepted: string;
            invitationDeclined: string;
            invitationExpired: string;
            invitationInvalid: string;
            alreadyMember: string;
            pendingInvitations: string;
            sentInvitations: string;
            receivedInvitations: string;
            invitationDetails: string;
            expiresAt: string;
            customMessage: string;
        };
    };

    // Validation messages
    validation: {
        required: string;
        email: string;
        phone: string;
        url: string;
        minLength: string;
        maxLength: string;
        min: string;
        max: string;
        pattern: string;
        passwordMismatch: string;
        invalidFormat: string;
        invalid: string;
        tooShort: string;
        tooLong: string;
        tooSmall: string;
        tooLarge: string;
        notFound: string;
        alreadyExists: string;
        expired: string;
        weak: string;
        strong: string;
        medium: string;
        passwordStrength: {
            veryWeak: string;
            weak: string;
            fair: string;
            good: string;
            strong: string;
        };
        passwordRequirements: {
            minLength: string;
            uppercase: string;
            lowercase: string;
            number: string;
            symbol: string;
        };
    };

    // Error messages
    errors: {
        // Generic errors
        generic: {
            unknown: string;
            network: string;
            timeout: string;
            serverError: string;
            notFound: string;
            unauthorized: string;
            forbidden: string;
            badRequest: string;
            conflict: string;
            tooManyRequests: string;
            maintenance: string;
            offline: string;
        };

        // Authentication errors
        auth: {
            invalidCredentials: string;
            accountLocked: string;
            accountDisabled: string;
            accountNotVerified: string;
            sessionExpired: string;
            invalidToken: string;
            mfaRequired: string;
            invalidMfaCode: string;
            passkeyNotSupported: string;
            passkeyFailed: string;
            oauthFailed: string;
            oauthCancelled: string;
            magicLinkExpired: string;
            magicLinkInvalid: string;
            passwordTooWeak: string;
            passwordReused: string;
            emailNotVerified: string;
            phoneNotVerified: string;
            invitationExpired: string;
            invitationInvalid: string;
            invitationAlreadyAccepted: string;
        };

        // Organization errors
        organization: {
            notFound: string;
            accessDenied: string;
            memberLimitReached: string;
            ownerRequired: string;
            cannotRemoveOwner: string;
            cannotRemoveSelf: string;
            alreadyMember: string;
            notMember: string;
            invalidRole: string;
            roleNotFound: string;
            domainTaken: string;
            domainInvalid: string;
            seatLimitReached: string;
            subscriptionRequired: string;
            paymentFailed: string;
        };

        // Validation errors
        validation: {
            invalidEmail: string;
            invalidPhone: string;
            invalidUrl: string;
            fieldRequired: string;
            fieldTooShort: string;
            fieldTooLong: string;
            fieldInvalid: string;
            passwordsDoNotMatch: string;
            emailTaken: string;
            usernameTaken: string;
            phoneNumberTaken: string;
            domainTaken: string;
        };
    };

    // Success messages
    success: {
        generic: {
            saved: string;
            updated: string;
            created: string;
            deleted: string;
            sent: string;
            completed: string;
            copied: string;
            uploaded: string;
            downloaded: string;
            imported: string;
            exported: string;
        };

        auth: {
            signedIn: string;
            signedUp: string;
            signedOut: string;
            passwordChanged: string;
            passwordReset: string;
            emailVerified: string;
            phoneVerified: string;
            mfaEnabled: string;
            mfaDisabled: string;
            passkeyAdded: string;
            passkeyRemoved: string;
            accountConnected: string;
            accountDisconnected: string;
        };

        organization: {
            created: string;
            updated: string;
            deleted: string;
            memberInvited: string;
            memberRemoved: string;
            roleChanged: string;
            ownershipTransferred: string;
            settingsUpdated: string;
            domainVerified: string;
            subscriptionUpdated: string;
            paymentMethodUpdated: string;
        };
    };

    // Component-specific messages
    components: {
        // Loading states
        loading: {
            generic: string;
            signIn: string;
            signUp: string;
            profile: string;
            organization: string;
            members: string;
            settings: string;
            verification: string;
            mfa: string;
            passkey: string;
            oauth: string;
        };

        // Empty states
        empty: {
            generic: string;
            members: string;
            invitations: string;
            sessions: string;
            devices: string;
            notifications: string;
            history: string;
            logs: string;
            search: string;
            filter: string;
        };

        // Confirmation dialogs
        confirm: {
            delete: string;
            remove: string;
            cancel: string;
            logout: string;
            transfer: string;
            disable: string;
            enable: string;
            reset: string;
            clear: string;
            proceed: string;
            areYouSure: string;
            cannotUndo: string;
            permanentAction: string;
        };

        // Tooltips and help text
        help: {
            password: string;
            mfa: string;
            passkey: string;
            backup: string;
            domain: string;
            webhook: string;
            apiKey: string;
            role: string;
            permission: string;
            billing: string;
            usage: string;
        };
    };
}