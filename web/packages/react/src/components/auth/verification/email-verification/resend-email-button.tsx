// ============================================================================
// Resend Email Button Component
// ============================================================================

import { withErrorBoundary } from "@/components";
import { Button } from "@/components/ui";
import { ArrowPathIcon } from "@heroicons/react/24/outline";
import React from "react";
import type { ResendEmailButtonProps } from "./email-verification";

export const ResendEmailButton = withErrorBoundary(function ResendEmailButton({
	onResend,
	disabled = false,
	remainingTime = 0,
	attempt = 0,
	maxAttempts = 3,
	className,
	size = "md",
	radius = "md",
}: ResendEmailButtonProps) {
	const canResend = remainingTime === 0 && attempt < maxAttempts;
	const attemptsLeft = maxAttempts - attempt;

	return (
		<Button
			color="primary"
			variant="light"
			size={size}
			radius={radius}
			onClick={onResend}
			disabled={disabled || !canResend}
			className={className}
			startContent={
				!canResend ? undefined : <ArrowPathIcon className="h-3 w-3" />
			}
		>
			{remainingTime > 0
				? `Resend in ${remainingTime}s`
				: attempt >= maxAttempts
					? "Max attempts reached"
					: `Resend${attempt > 0 ? ` (${attemptsLeft} left)` : ""}`}
		</Button>
	);
});
