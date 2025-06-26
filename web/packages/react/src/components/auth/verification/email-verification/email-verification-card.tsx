import {withErrorBoundary} from "@/components/auth/common";
import {EmailVerification, type EmailVerificationCardProps} from "./email-verification";
import {Card, CardBody} from "@heroui/react";


export const EmailVerificationCard = withErrorBoundary(function EmailVerificationCard({
                                                                                          variant = 'shadow',
                                                                                          radius = 'lg',
                                                                                          ...props
                                                                                      }: EmailVerificationCardProps) {
    return (
        <Card
            className={`max-w-md mx-auto ${props.className || ''}`}
            variant={variant}
            radius={radius}
        >
            <CardBody className="p-6">
                <EmailVerification {...props} />
            </CardBody>
        </Card>
    );
});