// ============================================================================
// Email Verification Modal Component
// ============================================================================

import { withErrorBoundary } from "@/components/auth/common";
import { Modal, ModalBody, ModalHeader } from "@/components/ui";
import React from "react";
import {
	EmailVerification,
	type EmailVerificationModalProps,
} from "./email-verification";

export const EmailVerificationModal = withErrorBoundary(
	function EmailVerificationModal({
		isOpen,
		onClose,
		isDismissable = true,
		...props
	}: EmailVerificationModalProps) {
		return (
			<Modal
				isOpen={isOpen}
				onClose={onClose}
				isDismissable={isDismissable}
				size={props.modalSize}
				classNames={{
					backdrop:
						"bg-gradient-to-t from-zinc-900 to-zinc-900/10 backdrop-opacity-20",
				}}
			>
				<ModalHeader className="flex flex-col gap-1">
					Email Verification
				</ModalHeader>
				<ModalBody>
					<EmailVerification {...props} />
				</ModalBody>
			</Modal>
		);
	},
);
