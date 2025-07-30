/**
 * @frank-auth/react - Organization Invitation Components
 *
 * Handles organization invitation acceptance flow with token validation,
 * preview, accept/decline actions, and post-invitation redirects.
 */

import {
	Avatar,
	Badge,
	Button,
	Card,
	CardBody,
	CardHeader,
	Divider,
	Input,
} from "@/components/ui";
import {
	BuildingOfficeIcon,
	CheckCircleIcon,
	ClockIcon,
	ExclamationTriangleIcon,
	ShieldCheckIcon,
	XCircleIcon,
} from "@heroicons/react/24/outline";
import type React from "react";
import { useCallback, useEffect, useState } from "react";

import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import { withErrorBoundary } from "../common/error-boundary";

// ============================================================================
// Types
// ============================================================================

export interface InvitationData {
	id: string;
	token: string;
	email: string;
	organizationId: string;
	organizationName: string;
	organizationLogo?: string;
	roleId: string;
	roleName: string;
	invitedBy: string;
	invitedByName?: string;
	invitedByAvatar?: string;
	expiresAt: string;
	message?: string;
	customFields?: Record<string, any>;
	redirectUrl?: string;
}

export interface InviteAcceptanceProps {
	token?: string;
	onAcceptSuccess?: (result: {
		organizationId: string;
		userId: string;
	}) => void;
	onDeclineSuccess?: () => void;
	onError?: (error: Error) => void;
	className?: string;
	style?: React.CSSProperties;
}

export interface InvitePreviewProps {
	invitation: InvitationData;
	onAccept?: () => void;
	onDecline?: () => void;
	isLoading?: boolean;
	className?: string;
}

export interface InviteAcceptFormProps {
	invitation: InvitationData;
	onSubmit: (userData: {
		firstName?: string;
		lastName?: string;
		password?: string;
	}) => void;
	isLoading?: boolean;
	requiresSignUp?: boolean;
	className?: string;
}

export interface InviteStatusProps {
	status:
		| "validating"
		| "valid"
		| "accepted"
		| "declined"
		| "expired"
		| "invalid"
		| "error";
	invitation?: InvitationData;
	error?: string;
	className?: string;
}

// ============================================================================
// Hook for Invitation Management
// ============================================================================

interface UseInvitationProps {
	token?: string;
	onAcceptSuccess?: (result: {
		organizationId: string;
		userId: string;
	}) => void;
	onDeclineSuccess?: () => void;
	onError?: (error: Error) => void;
}

function useInvitation({
	token,
	onAcceptSuccess,
	onDeclineSuccess,
	onError,
}: UseInvitationProps) {
	const { client, user } = useAuth();
	const [invitation, setInvitation] = useState<InvitationData | null>(null);
	const [status, setStatus] = useState<
		| "idle"
		| "validating"
		| "valid"
		| "accepting"
		| "declining"
		| "accepted"
		| "declined"
		| "expired"
		| "invalid"
		| "error"
	>("idle");
	const [error, setError] = useState<string | null>(null);

	const validateInvitation = useCallback(
		async (invitationToken: string) => {
			try {
				setStatus("validating");
				setError(null);

				const response = await client.invitations.validateInvitation({
					invitationValidationRequest: {
						token: invitationToken,
					},
				});

				if (response.valid && response.invitation) {
					setInvitation(response.invitation);

					// Check if invitation is expired
					const expiresAt = new Date(response.invitation.expiresAt);
					if (expiresAt < new Date()) {
						setStatus("expired");
						setError("This invitation has expired");
					} else {
						setStatus("valid");
					}
				} else {
					setStatus("invalid");
					setError(response.message || "Invalid invitation token");
				}
			} catch (err) {
				const error =
					err instanceof Error
						? err
						: new Error("Failed to validate invitation");
				setStatus("error");
				setError(error.message);
				onError?.(error);
			}
		},
		[client, onError],
	);

	const acceptInvitation = useCallback(
		async (userData?: {
			firstName?: string;
			lastName?: string;
			password?: string;
		}) => {
			if (!invitation) {
				setError("No invitation data available");
				return;
			}

			try {
				setStatus("accepting");
				setError(null);

				const acceptRequest: any = {
					token: invitation.token,
				};

				// Add user data if provided (for sign-up flow)
				if (userData) {
					acceptRequest.userData = userData;
				}

				const response = await client.invitations.acceptInvitation({
					acceptInvitationRequest: acceptRequest,
				});

				if (response.success) {
					setStatus("accepted");
					onAcceptSuccess?.({
						organizationId: invitation.organizationId,
						userId: response.userId || user?.id || "",
					});

					// Handle redirect if specified
					if (invitation.redirectUrl) {
						setTimeout(() => {
							window.location.href = invitation.redirectUrl!;
						}, 2000);
					}
				} else {
					throw new Error(response.message || "Failed to accept invitation");
				}
			} catch (err) {
				const error =
					err instanceof Error ? err : new Error("Failed to accept invitation");
				setStatus("error");
				setError(error.message);
				onError?.(error);
			}
		},
		[invitation, client, user, onAcceptSuccess, onError],
	);

	const declineInvitation = useCallback(async () => {
		if (!invitation) {
			setError("No invitation data available");
			return;
		}

		try {
			setStatus("declining");
			setError(null);

			const response = await client.invitations.declineInvitation({
				declineInvitationRequest: {
					token: invitation.token,
				},
			});

			if (response.success) {
				setStatus("declined");
				onDeclineSuccess?.();
			} else {
				throw new Error(response.message || "Failed to decline invitation");
			}
		} catch (err) {
			const error =
				err instanceof Error ? err : new Error("Failed to decline invitation");
			setStatus("error");
			setError(error.message);
			onError?.(error);
		}
	}, [invitation, client, onDeclineSuccess, onError]);

	// Auto-validate when token is provided
	useEffect(() => {
		if (token && status === "idle") {
			validateInvitation(token);
		}
	}, [token, status, validateInvitation]);

	// Extract token from URL if not provided
	useEffect(() => {
		if (!token && typeof window !== "undefined") {
			const urlParams = new URLSearchParams(window.location.search);
			const urlToken =
				urlParams.get("invitation_token") || urlParams.get("invite");

			if (urlToken && status === "idle") {
				validateInvitation(urlToken);
			}
		}
	}, [token, status, validateInvitation]);

	return {
		invitation,
		status,
		error,
		validateInvitation,
		acceptInvitation,
		declineInvitation,
		isLoading:
			status === "validating" ||
			status === "accepting" ||
			status === "declining",
	};
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatExpirationDate(expiresAt: string): string {
	const date = new Date(expiresAt);
	const now = new Date();
	const diffMs = date.getTime() - now.getTime();
	const diffHours = Math.ceil(diffMs / (1000 * 60 * 60));
	const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

	if (diffMs <= 0) {
		return "Expired";
	} else if (diffHours <= 24) {
		return `Expires in ${diffHours} hour${diffHours !== 1 ? "s" : ""}`;
	} else {
		return `Expires in ${diffDays} day${diffDays !== 1 ? "s" : ""}`;
	}
}

function getInvitationStatus(
	expiresAt: string,
): "active" | "expiring" | "expired" {
	const date = new Date(expiresAt);
	const now = new Date();
	const diffMs = date.getTime() - now.getTime();
	const diffHours = diffMs / (1000 * 60 * 60);

	if (diffMs <= 0) return "expired";
	if (diffHours <= 24) return "expiring";
	return "active";
}

// ============================================================================
// Invite Acceptance Component
// ============================================================================

export const InviteAcceptance = withErrorBoundary(function InviteAcceptance({
	token,
	onAcceptSuccess,
	onDeclineSuccess,
	onError,
	className,
	style,
}: InviteAcceptanceProps) {
	const { user } = useAuth();
	const { config } = useConfig();
	const {
		invitation,
		status,
		error,
		acceptInvitation,
		declineInvitation,
		isLoading,
	} = useInvitation({
		token,
		onAcceptSuccess,
		onDeclineSuccess,
		onError,
	});

	const handleAccept = async (userData?: {
		firstName?: string;
		lastName?: string;
		password?: string;
	}) => {
		await acceptInvitation(userData);
	};

	const handleDecline = async () => {
		await declineInvitation();
	};

	const renderContent = () => {
		if (status === "validating") {
			return <InviteStatus status="validating" />;
		}

		if (status === "invalid" || status === "error") {
			return (
				<InviteStatus
					status={status === "invalid" ? "invalid" : "error"}
					error={error || undefined}
				/>
			);
		}

		if (status === "expired") {
			return (
				<InviteStatus status="expired" invitation={invitation || undefined} />
			);
		}

		if (status === "accepted") {
			return (
				<InviteStatus status="accepted" invitation={invitation || undefined} />
			);
		}

		if (status === "declined") {
			return (
				<InviteStatus status="declined" invitation={invitation || undefined} />
			);
		}

		if (invitation && status === "valid") {
			return (
				<div className="space-y-6">
					<InvitePreview
						invitation={invitation}
						onAccept={() => handleAccept()}
						onDecline={handleDecline}
						isLoading={isLoading}
					/>

					{!user && (
						<InviteAcceptForm
							invitation={invitation}
							onSubmit={handleAccept}
							isLoading={isLoading}
							requiresSignUp={true}
						/>
					)}
				</div>
			);
		}

		return null;
	};

	return (
		<div className={className} style={style}>
			{renderContent()}
		</div>
	);
});

// ============================================================================
// Invite Preview Component
// ============================================================================

export const InvitePreview = withErrorBoundary(function InvitePreview({
	invitation,
	onAccept,
	onDecline,
	isLoading = false,
	className,
}: InvitePreviewProps) {
	const invitationStatus = getInvitationStatus(invitation.expiresAt);
	const expirationText = formatExpirationDate(invitation.expiresAt);

	return (
		<Card className={`max-w-md mx-auto ${className || ""}`} variant="shadow">
			<CardHeader className="flex flex-col items-center pb-2">
				<div className="flex items-center justify-center w-16 h-16 bg-primary-100 rounded-full mb-4">
					<BuildingOfficeIcon className="h-8 w-8 text-primary" />
				</div>
				<h2 className="text-xl font-bold text-center">
					Organization Invitation
				</h2>
				<Badge
					color={
						invitationStatus === "expired"
							? "danger"
							: invitationStatus === "expiring"
								? "warning"
								: "success"
					}
					variant="flat"
					className="mt-2"
				>
					{expirationText}
				</Badge>
			</CardHeader>

			<CardBody className="space-y-6">
				{/* Organization Info */}
				<div className="text-center">
					<div className="flex items-center justify-center mb-3">
						{invitation.organizationLogo ? (
							<Avatar
								src={invitation.organizationLogo}
								alt={invitation.organizationName}
								size="lg"
								className="mr-3"
							/>
						) : (
							<div className="w-12 h-12 bg-default-200 rounded-full flex items-center justify-center mr-3">
								<BuildingOfficeIcon className="h-6 w-6 text-default-500" />
							</div>
						)}
						<div>
							<h3 className="text-lg font-semibold">
								{invitation.organizationName}
							</h3>
							<p className="text-sm text-default-500">
								wants you to join their organization
							</p>
						</div>
					</div>
				</div>

				<Divider />

				{/* Invitation Details */}
				<div className="space-y-4">
					<div className="flex items-center justify-between">
						<span className="text-sm text-default-600">Email:</span>
						<span className="text-sm font-medium">{invitation.email}</span>
					</div>

					<div className="flex items-center justify-between">
						<span className="text-sm text-default-600">Role:</span>
						<Badge
							color="primary"
							variant="flat"
							startContent={<ShieldCheckIcon className="h-3 w-3" />}
						>
							{invitation.roleName}
						</Badge>
					</div>

					{invitation.invitedByName && (
						<div className="flex items-center justify-between">
							<span className="text-sm text-default-600">Invited by:</span>
							<div className="flex items-center gap-2">
								{invitation.invitedByAvatar && (
									<Avatar src={invitation.invitedByAvatar} size="sm" />
								)}
								<span className="text-sm font-medium">
									{invitation.invitedByName}
								</span>
							</div>
						</div>
					)}
				</div>

				{/* Custom Message */}
				{invitation.message && (
					<>
						<Divider />
						<div className="bg-default-50 p-4 rounded-lg">
							<p className="text-sm text-default-700 italic">
								"{invitation.message}"
							</p>
						</div>
					</>
				)}

				{/* Action Buttons */}
				<div className="flex gap-3 pt-4">
					<Button
						color="success"
						variant="solid"
						className="flex-1"
						onClick={onAccept}
						isLoading={isLoading}
						disabled={invitationStatus === "expired"}
						startContent={<CheckCircleIcon className="h-4 w-4" />}
					>
						Accept Invitation
					</Button>

					<Button
						color="danger"
						variant="flat"
						className="flex-1"
						onClick={onDecline}
						isLoading={isLoading}
						disabled={invitationStatus === "expired"}
						startContent={<XCircleIcon className="h-4 w-4" />}
					>
						Decline
					</Button>
				</div>
			</CardBody>
		</Card>
	);
});

// ============================================================================
// Invite Accept Form Component
// ============================================================================

export const InviteAcceptForm = withErrorBoundary(function InviteAcceptForm({
	invitation,
	onSubmit,
	isLoading = false,
	requiresSignUp = false,
	className,
}: InviteAcceptFormProps) {
	const [formData, setFormData] = useState({
		firstName: "",
		lastName: "",
		password: "",
		confirmPassword: "",
	});
	const [errors, setErrors] = useState<Record<string, string>>({});

	const handleInputChange = (field: string, value: string) => {
		setFormData((prev) => ({ ...prev, [field]: value }));
		if (errors[field]) {
			setErrors((prev) => ({ ...prev, [field]: "" }));
		}
	};

	const validateForm = (): boolean => {
		const newErrors: Record<string, string> = {};

		if (requiresSignUp) {
			if (!formData.firstName.trim()) {
				newErrors.firstName = "First name is required";
			}

			if (!formData.lastName.trim()) {
				newErrors.lastName = "Last name is required";
			}

			if (!formData.password) {
				newErrors.password = "Password is required";
			} else if (formData.password.length < 8) {
				newErrors.password = "Password must be at least 8 characters";
			}

			if (formData.password !== formData.confirmPassword) {
				newErrors.confirmPassword = "Passwords do not match";
			}
		}

		setErrors(newErrors);
		return Object.keys(newErrors).length === 0;
	};

	const handleSubmit = (e: React.FormEvent) => {
		e.preventDefault();

		if (!validateForm()) return;

		const userData = requiresSignUp
			? {
					firstName: formData.firstName,
					lastName: formData.lastName,
					password: formData.password,
				}
			: undefined;

		onSubmit(userData);
	};

	if (!requiresSignUp) {
		return null;
	}

	return (
		<Card className={`max-w-md mx-auto ${className || ""}`} variant="flat">
			<CardHeader>
				<h3 className="text-lg font-semibold">Complete Your Profile</h3>
				<p className="text-sm text-default-500">
					Create your account to join {invitation.organizationName}
				</p>
			</CardHeader>

			<CardBody>
				<form onSubmit={handleSubmit} className="space-y-4">
					<div className="grid grid-cols-2 gap-3">
						<Input
							label="First Name"
							placeholder="Enter your first name"
							value={formData.firstName}
							onChange={(e) => handleInputChange("firstName", e.target.value)}
							isInvalid={!!errors.firstName}
							errorMessage={errors.firstName}
							disabled={isLoading}
							required
						/>

						<Input
							label="Last Name"
							placeholder="Enter your last name"
							value={formData.lastName}
							onChange={(e) => handleInputChange("lastName", e.target.value)}
							isInvalid={!!errors.lastName}
							errorMessage={errors.lastName}
							disabled={isLoading}
							required
						/>
					</div>

					<Input
						type="password"
						label="Password"
						placeholder="Create a strong password"
						value={formData.password}
						onChange={(e) => handleInputChange("password", e.target.value)}
						isInvalid={!!errors.password}
						errorMessage={errors.password}
						disabled={isLoading}
						required
					/>

					<Input
						type="password"
						label="Confirm Password"
						placeholder="Confirm your password"
						value={formData.confirmPassword}
						onChange={(e) =>
							handleInputChange("confirmPassword", e.target.value)
						}
						isInvalid={!!errors.confirmPassword}
						errorMessage={errors.confirmPassword}
						disabled={isLoading}
						required
					/>

					<Button
						type="submit"
						color="primary"
						className="w-full"
						isLoading={isLoading}
						disabled={isLoading}
					>
						Join Organization
					</Button>
				</form>
			</CardBody>
		</Card>
	);
});

// ============================================================================
// Invite Status Component
// ============================================================================

export const InviteStatus = withErrorBoundary(function InviteStatus({
	status,
	invitation,
	error,
	className,
}: InviteStatusProps) {
	const getStatusConfig = () => {
		switch (status) {
			case "validating":
				return {
					icon: <ClockIcon className="h-16 w-16 text-primary animate-spin" />,
					title: "Validating Invitation",
					message: "Please wait while we verify your invitation...",
					color: "primary",
				};
			case "valid":
				return {
					icon: <CheckCircleIcon className="h-16 w-16 text-success" />,
					title: "Valid Invitation",
					message: "Your invitation is valid and ready to accept.",
					color: "success",
				};
			case "accepted":
				return {
					icon: <CheckCircleIcon className="h-16 w-16 text-success" />,
					title: "Invitation Accepted!",
					message: invitation
						? `Welcome to ${invitation.organizationName}! You've been added as ${invitation.roleName}.`
						: "Your invitation has been accepted successfully.",
					color: "success",
				};
			case "declined":
				return {
					icon: <XCircleIcon className="h-16 w-16 text-default-500" />,
					title: "Invitation Declined",
					message: "You have declined this organization invitation.",
					color: "default",
				};
			case "expired":
				return {
					icon: <ExclamationTriangleIcon className="h-16 w-16 text-warning" />,
					title: "Invitation Expired",
					message:
						"This invitation has expired. Please request a new invitation from the organization.",
					color: "warning",
				};
			case "invalid":
				return {
					icon: <XCircleIcon className="h-16 w-16 text-danger" />,
					title: "Invalid Invitation",
					message: "This invitation link is invalid or has already been used.",
					color: "danger",
				};
			case "error":
				return {
					icon: <ExclamationTriangleIcon className="h-16 w-16 text-danger" />,
					title: "Error",
					message:
						error || "An error occurred while processing your invitation.",
					color: "danger",
				};
			default:
				return {
					icon: <ClockIcon className="h-16 w-16 text-default-500" />,
					title: "Unknown Status",
					message: "Unable to determine invitation status.",
					color: "default",
				};
		}
	};

	const config = getStatusConfig();

	return (
		<Card className={`max-w-md mx-auto ${className || ""}`} variant="flat">
			<CardBody className="text-center py-8">
				<div className="flex justify-center mb-6">{config.icon}</div>

				<h2 className="text-xl font-semibold mb-3">{config.title}</h2>
				<p className="text-default-600 mb-6">{config.message}</p>

				{status === "accepted" && invitation?.redirectUrl && (
					<p className="text-sm text-default-500">
						Redirecting you to the organization dashboard...
					</p>
				)}

				{(status === "expired" ||
					status === "invalid" ||
					status === "error") && (
					<Button
						color="primary"
						variant="flat"
						onClick={() => (window.location.href = "/")}
					>
						Return to Home
					</Button>
				)}
			</CardBody>
		</Card>
	);
});

// ============================================================================
// Export All Components
// ============================================================================

export const InvitationComponents = {
	InviteAcceptance,
	InvitePreview,
	InviteAcceptForm,
	InviteStatus,
};
