import {useAuth} from "./use-auth";
import {useIdentityVerification, useInvitation} from "./use-invitation";
import {toast} from "sonner";
import {InvitationUtils} from "@/utils/invitation";

export function useVerificationFlow() {
    const { user, organization } = useAuth();

    const verification = useIdentityVerification({
        email: user?.email,
        phoneNumber: user?.phoneNumber,
        userId: user?.id,
        organizationId: organization?.id,
        methods: ['email', 'phone'],
    });

    const startVerification = (method: 'email' | 'phone') => {
        if (method === 'email') {
            verification.sendEmailCode();
        } else {
            verification.sendPhoneCode();
        }

        toast.success(`Sending ${method} verification code...`);
    };

    const progress = {
        total: verification.availableMethods.length,
        completed: verification.verifiedMethods.length,
        percentage: (verification.verifiedMethods.length / verification.availableMethods.length) * 100
    };

    return {
        ...verification,
        startVerification,
        progress,
        isComplete: verification.isVerified
    };
}

export function useInvitationFlow() {
    const invitation = useInvitation({ autoValidate: true });

    const handleAccept = async (userData?: any) => {
        try {
            const result = await invitation.acceptInvitation(userData);

            InvitationUtils.trackInvitationEvent('accepted', invitation.invitation, {
                userId: result.userId,
                organizationId: result.organizationId
            });

            toast.success('🎉 Welcome to the organization!');

            // Redirect with delay
            setTimeout(() => {
                if (result.redirectUrl) {
                    window.location.href = result.redirectUrl;
                } else {
                    window.location.href = `/dashboard?org=${result.organizationId}`;
                }
            }, 2000);
        } catch (error) {
            toast.error('Failed to accept invitation');
            console.error('Invitation acceptance error:', error);
        }
    };

    const handleDecline = async () => {
        try {
            await invitation.declineInvitation();

            InvitationUtils.trackInvitationEvent('declined', invitation.invitation);

            toast.info('Invitation declined');

            setTimeout(() => {
                window.location.href = '/';
            }, 1000);
        } catch (error) {
            toast.error('Failed to decline invitation');
            console.error('Invitation decline error:', error);
        }
    };

    return {
        ...invitation,
        handleAccept,
        handleDecline
    };
}