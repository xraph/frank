/**
 * @frank-auth/react - MFA Setup Component
 *
 * Multi-Factor Authentication setup and management interface
 * supporting TOTP, SMS, Email, and Backup codes.
 */

"use client";

import {
	Alert,
	Button,
	Card,
	CardBody,
	CardHeader,
	Chip,
	Code,
	Divider,
	Image,
	Modal,
	ModalBody,
	ModalContent,
	ModalHeader,
	Snippet,
	Tab,
	Tabs,
	useDisclosure,
} from "@heroui/react";
import React from "react";
import { useConfig } from "../../../hooks/use-config";
import { useMFA } from "../../../hooks/use-mfa";
import { PhoneField } from "../../forms/phone-field";
import { VerificationCode } from "../../forms/verification-code";

// ============================================================================
// MFA Setup Interface
// ============================================================================

export interface MFASetupProps {
	/**
	 * Success callback
	 */
	onSuccess?: (message: string) => void;

	/**
	 * Error callback
	 */
	onError?: (error: string) => void;

	/**
	 * Show TOTP setup
	 */
	showTOTPSetup?: boolean;

	/**
	 * Show SMS setup
	 */
	showSMSSetup?: boolean;

	/**
	 * Show Email setup
	 */
	showEmailSetup?: boolean;

	/**
	 * Show backup codes
	 */
	showBackupCodes?: boolean;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Whether component is disabled
	 */
	isDisabled?: boolean;

	/**
	 * Component variant
	 */
	variant?: "flat" | "bordered" | "shadow";

	/**
	 * Component size
	 */
	size?: "sm" | "md" | "lg";

	/**
	 * Default active method
	 */
	defaultMethod?: string;

	/**
	 * Hide specific methods
	 */
	hideMethods?: string[];

	/**
	 * Custom method configurations
	 */
	customMethods?: MFAMethodConfig[];
}

export interface MFAMethodConfig {
	key: string;
	name: string;
	description: string;
	icon: React.ReactNode;
	setupComponent: React.ReactNode;
}

// ============================================================================
// TOTP Setup Component
// ============================================================================

interface TOTPSetupProps {
	onSuccess: (message: string) => void;
	onError: (error: string) => void;
	onClose: () => void;
	isOpen: boolean;
}

function TOTPSetup({ onSuccess, onError, onClose, isOpen }: TOTPSetupProps) {
	const { setupTOTP, verifySetup } = useMFA();

	const [step, setStep] = React.useState<"setup" | "verify">("setup");
	const [setupData, setSetupData] = React.useState<any>(null);
	const [verificationCode, setVerificationCode] = React.useState("");
	const [isLoading, setIsLoading] = React.useState(false);

	// Reset state when modal opens/closes
	React.useEffect(() => {
		if (!isOpen) {
			setStep("setup");
			setSetupData(null);
			setVerificationCode("");
		}
	}, [isOpen]);

	// Handle TOTP setup initiation
	const handleSetup = async () => {
		try {
			setIsLoading(true);
			const data = await setupTOTP();
			setSetupData(data);
			setStep("verify");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to setup TOTP";
			onError(message);
		} finally {
			setIsLoading(false);
		}
	};

	// Handle verification
	const handleVerify = async () => {
		if (!verificationCode || verificationCode.length !== 6) {
			onError("Please enter a valid 6-digit code");
			return;
		}

		try {
			setIsLoading(true);
			await verifySetup("totp", verificationCode);
			onSuccess("TOTP authentication enabled successfully");
			onClose();
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to verify TOTP";
			onError(message);
		} finally {
			setIsLoading(false);
		}
	};

	return (
		<div className="space-y-4">
			{step === "setup" && (
				<div className="text-center space-y-4">
					<div className="flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mx-auto">
						<svg
							className="w-8 h-8 text-primary"
							fill="none"
							stroke="currentColor"
							viewBox="0 0 24 24"
						>
							<path
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={2}
								d="M12 18h.01M8 21h8a1 1 0 001-1V4a1 1 0 00-1-1H8a1 1 0 00-1 1v16a1 1 0 001 1z"
							/>
						</svg>
					</div>

					<div>
						<h3 className="text-lg font-semibold">Setup Authenticator App</h3>
						<p className="text-sm text-default-500 mt-2">
							We'll help you setup two-factor authentication using an
							authenticator app like Google Authenticator or Authy.
						</p>
					</div>

					<div className="text-left space-y-3">
						<div className="flex items-center gap-3">
							<div className="flex items-center justify-center w-6 h-6 bg-primary text-white text-xs rounded-full flex-shrink-0">
								1
							</div>
							<p className="text-sm">
								Install an authenticator app on your phone
							</p>
						</div>
						<div className="flex items-center gap-3">
							<div className="flex items-center justify-center w-6 h-6 bg-default-300 text-default-600 text-xs rounded-full flex-shrink-0">
								2
							</div>
							<p className="text-sm">
								Scan the QR code or enter the secret key
							</p>
						</div>
						<div className="flex items-center gap-3">
							<div className="flex items-center justify-center w-6 h-6 bg-default-300 text-default-600 text-xs rounded-full flex-shrink-0">
								3
							</div>
							<p className="text-sm">Enter the 6-digit code from your app</p>
						</div>
					</div>

					<Button
						color="primary"
						onPress={handleSetup}
						isLoading={isLoading}
						className="w-full"
					>
						Get Started
					</Button>
				</div>
			)}

			{step === "verify" && setupData && (
				<div className="space-y-4">
					<div className="text-center">
						<h3 className="text-lg font-semibold">Scan QR Code</h3>
						<p className="text-sm text-default-500 mt-2">
							Scan this QR code with your authenticator app, or enter the secret
							key manually.
						</p>
					</div>

					{/* QR Code */}
					{setupData.qrCode && (
						<div className="flex justify-center">
							<div className="p-4 bg-white rounded-lg border">
								<Image
									src={setupData.qrCode}
									alt="QR Code"
									width={200}
									height={200}
								/>
							</div>
						</div>
					)}

					{/* Secret Key */}
					{setupData.secret && (
						<div>
							<p className="text-sm font-medium mb-2">
								Or enter this secret key manually:
							</p>
							<Snippet size="sm" symbol="" className="w-full">
								{setupData.secret}
							</Snippet>
						</div>
					)}

					{/* Verification Code Input */}
					<div>
						<p className="text-sm font-medium mb-2">
							Enter the 6-digit code from your app:
						</p>
						<VerificationCode
							length={6}
							value={verificationCode}
							onChange={setVerificationCode}
							onComplete={handleVerify}
						/>
					</div>

					<div className="flex gap-2">
						<Button
							variant="light"
							onPress={() => setStep("setup")}
							isDisabled={isLoading}
							className="flex-1"
						>
							Back
						</Button>
						<Button
							color="primary"
							onPress={handleVerify}
							isLoading={isLoading}
							isDisabled={!verificationCode || verificationCode.length !== 6}
							className="flex-1"
						>
							Verify & Enable
						</Button>
					</div>
				</div>
			)}
		</div>
	);
}

// ============================================================================
// SMS Setup Component
// ============================================================================

interface SMSSetupProps {
	onSuccess: (message: string) => void;
	onError: (error: string) => void;
	onClose: () => void;
	isOpen: boolean;
}

function SMSSetup({ onSuccess, onError, onClose, isOpen }: SMSSetupProps) {
	const { setupSMS, verifySetup } = useMFA();

	const [step, setStep] = React.useState<"phone" | "verify">("phone");
	const [phoneNumber, setPhoneNumber] = React.useState("");
	const [verificationCode, setVerificationCode] = React.useState("");
	const [isLoading, setIsLoading] = React.useState(false);

	// Reset state when modal opens/closes
	React.useEffect(() => {
		if (!isOpen) {
			setStep("phone");
			setPhoneNumber("");
			setVerificationCode("");
		}
	}, [isOpen]);

	// Handle SMS setup
	const handleSetup = async () => {
		if (!phoneNumber) {
			onError("Please enter a valid phone number");
			return;
		}

		try {
			setIsLoading(true);
			await setupSMS(phoneNumber);
			setStep("verify");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to setup SMS";
			onError(message);
		} finally {
			setIsLoading(false);
		}
	};

	// Handle verification
	const handleVerify = async () => {
		if (!verificationCode || verificationCode.length !== 6) {
			onError("Please enter a valid 6-digit code");
			return;
		}

		try {
			setIsLoading(true);
			await verifySetup("sms", verificationCode);
			onSuccess("SMS authentication enabled successfully");
			onClose();
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to verify SMS";
			onError(message);
		} finally {
			setIsLoading(false);
		}
	};

	return (
		<div className="space-y-4">
			{step === "phone" && (
				<div className="space-y-4">
					<div className="text-center">
						<div className="flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mx-auto mb-4">
							<svg
								className="w-8 h-8 text-primary"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
								/>
							</svg>
						</div>

						<h3 className="text-lg font-semibold">Setup SMS Authentication</h3>
						<p className="text-sm text-default-500 mt-2">
							We'll send verification codes to your phone via SMS.
						</p>
					</div>

					<PhoneField
						label="Phone Number"
						placeholder="Enter your phone number"
						value={phoneNumber}
						onChange={setPhoneNumber}
						required
					/>

					<Button
						color="primary"
						onPress={handleSetup}
						isLoading={isLoading}
						isDisabled={!phoneNumber}
						className="w-full"
					>
						Send Verification Code
					</Button>
				</div>
			)}

			{step === "verify" && (
				<div className="space-y-4">
					<div className="text-center">
						<h3 className="text-lg font-semibold">Verify Phone Number</h3>
						<p className="text-sm text-default-500 mt-2">
							We sent a 6-digit code to {phoneNumber}. Enter it below to verify.
						</p>
					</div>

					<VerificationCode
						length={6}
						value={verificationCode}
						onChange={setVerificationCode}
						onComplete={handleVerify}
					/>

					<div className="flex gap-2">
						<Button
							variant="light"
							onPress={() => setStep("phone")}
							isDisabled={isLoading}
							className="flex-1"
						>
							Back
						</Button>
						<Button
							color="primary"
							onPress={handleVerify}
							isLoading={isLoading}
							isDisabled={!verificationCode || verificationCode.length !== 6}
							className="flex-1"
						>
							Verify & Enable
						</Button>
					</div>
				</div>
			)}
		</div>
	);
}

// ============================================================================
// Backup Codes Component
// ============================================================================

interface BackupCodesProps {
	codes: string[];
	onRegenerate: () => void;
	isLoading: boolean;
}

function BackupCodes({ codes, onRegenerate, isLoading }: BackupCodesProps) {
	const [showCodes, setShowCodes] = React.useState(false);

	return (
		<div className="space-y-4">
			<div className="text-center">
				<div className="flex items-center justify-center w-16 h-16 bg-warning/10 rounded-full mx-auto mb-4">
					<svg
						className="w-8 h-8 text-warning"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
						/>
					</svg>
				</div>

				<h3 className="text-lg font-semibold">Backup Codes</h3>
				<p className="text-sm text-default-500 mt-2">
					Save these backup codes in a secure place. Each code can only be used
					once.
				</p>
			</div>

			<Alert color="warning" variant="flat">
				<div className="space-y-2">
					<p className="text-sm font-medium">Important:</p>
					<ul className="text-xs space-y-1 ml-4">
						<li>• Store these codes in a secure location</li>
						<li>• Each code can only be used once</li>
						<li>• Generate new codes when you're running low</li>
					</ul>
				</div>
			</Alert>

			{codes.length > 0 && (
				<div>
					<div className="flex items-center justify-between mb-3">
						<p className="text-sm font-medium">Your backup codes:</p>
						<Button
							size="sm"
							variant="light"
							onPress={() => setShowCodes(!showCodes)}
						>
							{showCodes ? "Hide" : "Show"} Codes
						</Button>
					</div>

					{showCodes && (
						<div className="grid grid-cols-2 gap-2">
							{codes.map((code, index) => (
								<Code key={index} className="text-xs">
									{code}
								</Code>
							))}
						</div>
					)}
				</div>
			)}

			<Button
				color="primary"
				variant="bordered"
				onPress={onRegenerate}
				isLoading={isLoading}
				className="w-full"
			>
				Generate New Codes
			</Button>
		</div>
	);
}

// ============================================================================
// MFA Setup Component
// ============================================================================

export function MFASetup({
	onSuccess,
	onError,
	showTOTPSetup = true,
	showSMSSetup = true,
	showEmailSetup = false,
	showBackupCodes = true,
	className = "",
	isDisabled = false,
	variant = "bordered",
	size = "md",
	defaultMethod = "overview",
	hideMethods = [],
	customMethods = [],
}: MFASetupProps) {
	const {
		isEnabled,
		mfaMethods,
		backupCodes,
		hasTOTP,
		hasSMS,
		hasBackupCodes,
		removeMFAMethod,
		regenerateBackupCodes,
		disable,
		isLoading,
	} = useMFA();

	const { components } = useConfig();

	const totpModal = useDisclosure();
	const smsModal = useDisclosure();
	const [selectedTab, setSelectedTab] = React.useState(defaultMethod);

	// Custom component override
	const CustomMFASetup = components.MFASetup;
	if (CustomMFASetup) {
		return (
			<CustomMFASetup
				{...{
					onSuccess,
					onError,
					showTOTPSetup,
					showSMSSetup,
					showEmailSetup,
					showBackupCodes,
					className,
					isDisabled,
					variant,
					size,
					defaultMethod,
					hideMethods,
					customMethods,
				}}
			/>
		);
	}

	// Handle method removal
	const handleRemoveMethod = async (methodId: string) => {
		try {
			await removeMFAMethod(methodId);
			onSuccess?.("MFA method removed successfully");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to remove MFA method";
			onError?.(message);
		}
	};

	// Handle MFA disable
	const handleDisableMFA = async () => {
		try {
			await disable();
			onSuccess?.("Two-factor authentication disabled");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to disable MFA";
			onError?.(message);
		}
	};

	// Handle backup codes regeneration
	const handleRegenerateBackupCodes = async () => {
		try {
			await regenerateBackupCodes();
			onSuccess?.("Backup codes regenerated successfully");
		} catch (error) {
			const message =
				error instanceof Error
					? error.message
					: "Failed to regenerate backup codes";
			onError?.(message);
		}
	};

	return (
		<div className={`space-y-6 ${className}`}>
			{/* MFA Status */}
			<Card variant={variant}>
				<CardHeader>
					<div className="flex items-center justify-between w-full">
						<div className="flex items-center gap-3">
							<div
								className={`flex items-center justify-center w-10 h-10 rounded-lg ${
									isEnabled ? "bg-success/10" : "bg-default/10"
								}`}
							>
								<svg
									className={`w-5 h-5 ${isEnabled ? "text-success" : "text-default-400"}`}
									fill="none"
									stroke="currentColor"
									viewBox="0 0 24 24"
								>
									<path
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={2}
										d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
									/>
								</svg>
							</div>
							<div>
								<h4 className="text-md font-semibold">
									Two-Factor Authentication
								</h4>
								<div className="flex items-center gap-2">
									<Chip
										size="sm"
										color={isEnabled ? "success" : "default"}
										variant="flat"
									>
										{isEnabled ? "Enabled" : "Disabled"}
									</Chip>
									{isEnabled && (
										<span className="text-xs text-default-500">
											{mfaMethods.length} method
											{mfaMethods.length !== 1 ? "s" : ""} configured
										</span>
									)}
								</div>
							</div>
						</div>

						{isEnabled && (
							<Button
								variant="light"
								color="danger"
								size="sm"
								onPress={handleDisableMFA}
								isDisabled={isDisabled || isLoading}
							>
								Disable MFA
							</Button>
						)}
					</div>
				</CardHeader>

				{!isEnabled && (
					<>
						<Divider />
						<CardBody>
							<p className="text-sm text-default-600">
								Add an extra layer of security to your account by enabling
								two-factor authentication. Choose from authenticator apps, SMS,
								or backup codes.
							</p>
						</CardBody>
					</>
				)}
			</Card>

			{/* MFA Methods */}
			<Tabs
				selectedKey={selectedTab}
				onSelectionChange={(key) => setSelectedTab(key as string)}
				variant="bordered"
			>
				{/* Overview Tab */}
				<Tab key="overview" title="Overview">
					<div className="space-y-4">
						{/* TOTP Method */}
						{showTOTPSetup && !hideMethods.includes("totp") && (
							<Card variant="flat">
								<CardBody>
									<div className="flex items-center justify-between">
										<div className="flex items-center gap-3">
											<div className="flex items-center justify-center w-10 h-10 bg-primary/10 rounded-lg">
												<svg
													className="w-5 h-5 text-primary"
													fill="none"
													stroke="currentColor"
													viewBox="0 0 24 24"
												>
													<path
														strokeLinecap="round"
														strokeLinejoin="round"
														strokeWidth={2}
														d="M12 18h.01M8 21h8a1 1 0 001-1V4a1 1 0 00-1-1H8a1 1 0 00-1 1v16a1 1 0 001 1z"
													/>
												</svg>
											</div>
											<div>
												<p className="text-sm font-medium">Authenticator App</p>
												<p className="text-xs text-default-500">
													Use an app like Google Authenticator or Authy
												</p>
											</div>
										</div>

										<div className="flex items-center gap-2">
											{hasTOTP && (
												<Chip size="sm" color="success" variant="flat">
													Enabled
												</Chip>
											)}

											<Button
												size="sm"
												color={hasTOTP ? "danger" : "primary"}
												variant={hasTOTP ? "light" : "solid"}
												onPress={
													hasTOTP
														? () =>
																handleRemoveMethod(
																	mfaMethods.find((m) => m.type === "totp")
																		?.id || "",
																)
														: totpModal.onOpen
												}
												isDisabled={isDisabled}
											>
												{hasTOTP ? "Remove" : "Setup"}
											</Button>
										</div>
									</div>
								</CardBody>
							</Card>
						)}

						{/* SMS Method */}
						{showSMSSetup && !hideMethods.includes("sms") && (
							<Card variant="flat">
								<CardBody>
									<div className="flex items-center justify-between">
										<div className="flex items-center gap-3">
											<div className="flex items-center justify-center w-10 h-10 bg-secondary/10 rounded-lg">
												<svg
													className="w-5 h-5 text-secondary"
													fill="none"
													stroke="currentColor"
													viewBox="0 0 24 24"
												>
													<path
														strokeLinecap="round"
														strokeLinejoin="round"
														strokeWidth={2}
														d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
													/>
												</svg>
											</div>
											<div>
												<p className="text-sm font-medium">SMS</p>
												<p className="text-xs text-default-500">
													Receive codes via text message
												</p>
											</div>
										</div>

										<div className="flex items-center gap-2">
											{hasSMS && (
												<Chip size="sm" color="success" variant="flat">
													Enabled
												</Chip>
											)}

											<Button
												size="sm"
												color={hasSMS ? "danger" : "primary"}
												variant={hasSMS ? "light" : "solid"}
												onPress={
													hasSMS
														? () =>
																handleRemoveMethod(
																	mfaMethods.find((m) => m.type === "sms")
																		?.id || "",
																)
														: smsModal.onOpen
												}
												isDisabled={isDisabled}
											>
												{hasSMS ? "Remove" : "Setup"}
											</Button>
										</div>
									</div>
								</CardBody>
							</Card>
						)}
					</div>
				</Tab>

				{/* Backup Codes Tab */}
				{showBackupCodes && !hideMethods.includes("backup-codes") && (
					<Tab key="backup-codes" title="Backup Codes">
						<BackupCodes
							codes={backupCodes}
							onRegenerate={handleRegenerateBackupCodes}
							isLoading={isLoading}
						/>
					</Tab>
				)}

				{/* Custom Methods */}
				{customMethods.map(
					(method) =>
						!hideMethods.includes(method.key) && (
							<Tab key={method.key} title={method.name}>
								{method.setupComponent}
							</Tab>
						),
				)}
			</Tabs>

			{/* Setup Modals */}
			<Modal
				isOpen={totpModal.isOpen}
				onOpenChange={totpModal.onOpenChange}
				size="md"
				placement="center"
				hideCloseButton
			>
				<ModalContent>
					{(onClose) => (
						<>
							<ModalHeader />
							<ModalBody>
								<TOTPSetup
									onSuccess={(message) => {
										onSuccess?.(message);
										onClose();
									}}
									onError={(error) => onError?.(error)}
									onClose={onClose}
									isOpen={totpModal.isOpen}
								/>
							</ModalBody>
						</>
					)}
				</ModalContent>
			</Modal>

			<Modal
				isOpen={smsModal.isOpen}
				onOpenChange={smsModal.onOpenChange}
				size="md"
				placement="center"
				hideCloseButton
			>
				<ModalContent>
					{(onClose) => (
						<>
							<ModalHeader />
							<ModalBody>
								<SMSSetup
									onSuccess={(message) => {
										onSuccess?.(message);
										onClose();
									}}
									onError={(error) => onError?.(error)}
									onClose={onClose}
									isOpen={smsModal.isOpen}
								/>
							</ModalBody>
						</>
					)}
				</ModalContent>
			</Modal>
		</div>
	);
}

// ============================================================================
// Export
// ============================================================================

export default MFASetup;
