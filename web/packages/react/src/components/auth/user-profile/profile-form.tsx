/**
 * @frank-auth/react - Profile Form Component
 *
 * User profile editing form with image upload, field validation,
 * and real-time updates for personal information management.
 */

"use client";

import {
	Avatar,
	Button,
	Card,
	CardBody,
	CardHeader,
	Divider,
	Input,
	Select,
	SelectItem,
	Spinner,
	Switch,
	Textarea,
} from "@heroui/react";
import React from "react";
import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import { useUser } from "../../../hooks/use-user";
import { EmailField } from "../../forms/email-field";
import { PhoneField } from "../../forms/phone-field";

// ============================================================================
// Profile Form Interface
// ============================================================================

export interface ProfileFormProps {
	/**
	 * Form submission handler
	 */
	onSubmit?: (data: ProfileFormData) => void;

	/**
	 * Profile update handler
	 */
	onUpdate?: (data: ProfileFormData) => void;

	/**
	 * Success callback
	 */
	onSuccess?: (message: string) => void;

	/**
	 * Error callback
	 */
	onError?: (error: string) => void;

	/**
	 * Show save button
	 */
	showSaveButton?: boolean;

	/**
	 * Auto-save changes
	 */
	autoSave?: boolean;

	/**
	 * Auto-save delay (ms)
	 */
	autoSaveDelay?: number;

	/**
	 * Show profile image upload
	 */
	showImageUpload?: boolean;

	/**
	 * Show email field
	 */
	showEmail?: boolean;

	/**
	 * Show phone field
	 */
	showPhone?: boolean;

	/**
	 * Show username field
	 */
	showUsername?: boolean;

	/**
	 * Show metadata fields
	 */
	showMetadata?: boolean;

	/**
	 * Custom fields to display
	 */
	customFields?: ProfileFormField[];

	/**
	 * Hide specific fields
	 */
	hideFields?: string[];

	/**
	 * Field layout (columns)
	 */
	fieldLayout?: "single" | "double";

	/**
	 * Form variant
	 */
	variant?: "flat" | "bordered" | "faded";

	/**
	 * Form size
	 */
	size?: "sm" | "md" | "lg";

	/**
	 * Whether form is disabled
	 */
	isDisabled?: boolean;

	/**
	 * Whether form is loading
	 */
	isLoading?: boolean;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Show verification status
	 */
	showVerificationStatus?: boolean;

	/**
	 * Allow profile image removal
	 */
	allowImageRemoval?: boolean;

	/**
	 * Image upload handler
	 */
	onImageUpload?: (file: File) => Promise<string>;

	/**
	 * Image removal handler
	 */
	onImageRemove?: () => Promise<void>;

	/**
	 * Maximum file size for images (bytes)
	 */
	maxImageSize?: number;

	/**
	 * Allowed image types
	 */
	allowedImageTypes?: string[];
}

export interface ProfileFormData {
	firstName?: string;
	lastName?: string;
	email?: string;
	phone?: string;
	username?: string;
	profileImageUrl?: string;
	metadata?: Record<string, any>;
	customFields?: Record<string, any>;
}

export interface ProfileFormField {
	key: string;
	label: string;
	type: "text" | "email" | "phone" | "textarea" | "select" | "switch";
	placeholder?: string;
	description?: string;
	required?: boolean;
	options?: { value: string; label: string }[];
	validation?: (value: any) => string | null;
}

// ============================================================================
// Profile Form Component
// ============================================================================

export function ProfileForm({
	onSubmit,
	onUpdate,
	onSuccess,
	onError,
	showSaveButton = true,
	autoSave = false,
	autoSaveDelay = 1000,
	showImageUpload = true,
	showEmail = true,
	showPhone = true,
	showUsername = true,
	showMetadata = false,
	customFields = [],
	hideFields = [],
	fieldLayout = "single",
	variant = "bordered",
	size = "md",
	isDisabled = false,
	isLoading: externalLoading = false,
	className = "",
	showVerificationStatus = true,
	allowImageRemoval = true,
	onImageUpload,
	onImageRemove,
	maxImageSize = 5 * 1024 * 1024, // 5MB
	allowedImageTypes = ["image/jpeg", "image/png", "image/webp"],
}: ProfileFormProps) {
	const { user } = useAuth();
	const {
		updateProfile,
		updateProfileImage,
		removeProfileImage,
		isLoading: userLoading,
		isEmailVerified,
		isPhoneVerified,
	} = useUser();
	const { components } = useConfig();

	// Custom component override
	const CustomProfileForm = components.ProfileForm;
	if (CustomProfileForm) {
		return (
			<CustomProfileForm
				{...{
					onSubmit,
					onUpdate,
					onSuccess,
					onError,
					showSaveButton,
					autoSave,
					autoSaveDelay,
					showImageUpload,
					showEmail,
					showPhone,
					showUsername,
					showMetadata,
					customFields,
					hideFields,
					fieldLayout,
					variant,
					size,
					isDisabled,
					isLoading: externalLoading,
					className,
					showVerificationStatus,
					allowImageRemoval,
					onImageUpload,
					onImageRemove,
					maxImageSize,
					allowedImageTypes,
				}}
			/>
		);
	}

	// Form state
	const [formData, setFormData] = React.useState<ProfileFormData>({
		firstName: user?.firstName || "",
		lastName: user?.lastName || "",
		email: user?.primaryEmailAddress || "",
		phone: user?.primaryPhoneNumber || "",
		username: user?.username || "",
		profileImageUrl: user?.profileImageUrl || "",
		metadata: user?.unsafeMetadata || {},
		customFields: {},
	});

	const [isDirty, setIsDirty] = React.useState(false);
	const [isSaving, setIsSaving] = React.useState(false);
	const [imageUploading, setImageUploading] = React.useState(false);
	const [errors, setErrors] = React.useState<Record<string, string>>({});

	// Loading state
	const isLoading = externalLoading || userLoading || isSaving;

	// Auto-save timer
	const autoSaveTimer = React.useRef<NodeJS.Timeout>();

	// Update form data when user changes
	React.useEffect(() => {
		if (user) {
			setFormData({
				firstName: user.firstName || "",
				lastName: user.lastName || "",
				email: user.primaryEmailAddress || "",
				phone: user.primaryPhoneNumber || "",
				username: user.username || "",
				profileImageUrl: user.profileImageUrl || "",
				metadata: user.unsafeMetadata || {},
				customFields: {},
			});
		}
	}, [user]);

	// Auto-save functionality
	React.useEffect(() => {
		if (autoSave && isDirty && !isDisabled) {
			if (autoSaveTimer.current) {
				clearTimeout(autoSaveTimer.current);
			}

			autoSaveTimer.current = setTimeout(() => {
				handleSave();
			}, autoSaveDelay);
		}

		return () => {
			if (autoSaveTimer.current) {
				clearTimeout(autoSaveTimer.current);
			}
		};
	}, [formData, isDirty, autoSave, autoSaveDelay, isDisabled]);

	// Handle field change
	const handleFieldChange = React.useCallback(
		(field: string, value: any) => {
			setFormData((prev) => ({
				...prev,
				[field]: value,
			}));
			setIsDirty(true);

			// Clear field error
			if (errors[field]) {
				setErrors((prev) => {
					const newErrors = { ...prev };
					delete newErrors[field];
					return newErrors;
				});
			}
		},
		[errors],
	);

	// Handle custom field change
	const handleCustomFieldChange = React.useCallback(
		(field: string, value: any) => {
			setFormData((prev) => ({
				...prev,
				customFields: {
					...prev.customFields,
					[field]: value,
				},
			}));
			setIsDirty(true);
		},
		[],
	);

	// Validate form
	const validateForm = React.useCallback(() => {
		const newErrors: Record<string, string> = {};

		// Validate email
		if (showEmail && formData.email) {
			const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
			if (!emailRegex.test(formData.email)) {
				newErrors.email = "Please enter a valid email address";
			}
		}

		// Validate custom fields
		customFields.forEach((field) => {
			if (field.required && !formData.customFields?.[field.key]) {
				newErrors[field.key] = `${field.label} is required`;
			}

			if (field.validation && formData.customFields?.[field.key]) {
				const validationError = field.validation(
					formData.customFields[field.key],
				);
				if (validationError) {
					newErrors[field.key] = validationError;
				}
			}
		});

		setErrors(newErrors);
		return Object.keys(newErrors).length === 0;
	}, [formData, showEmail, customFields]);

	// Handle save
	const handleSave = React.useCallback(async () => {
		if (!validateForm()) {
			return;
		}

		try {
			setIsSaving(true);

			const updateData = {
				firstName: formData.firstName,
				lastName: formData.lastName,
				primaryEmailAddress: formData.email,
				primaryPhoneNumber: formData.phone,
				username: formData.username,
				unsafeMetadata: {
					...formData.metadata,
					...formData.customFields,
				},
			};

			await updateProfile(updateData);
			setIsDirty(false);

			onUpdate?.(formData);
			onSuccess?.("Profile updated successfully");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to update profile";
			onError?.(message);
		} finally {
			setIsSaving(false);
		}
	}, [formData, validateForm, updateProfile, onUpdate, onSuccess, onError]);

	// Handle submit
	const handleSubmit = React.useCallback(
		(e: React.FormEvent) => {
			e.preventDefault();

			if (onSubmit) {
				onSubmit(formData);
			} else {
				handleSave();
			}
		},
		[formData, onSubmit, handleSave],
	);

	// Handle image upload
	const handleImageUpload = React.useCallback(
		async (file: File) => {
			// Validate file
			if (!allowedImageTypes.includes(file.type)) {
				onError?.("Please select a valid image file (JPEG, PNG, or WebP)");
				return;
			}

			if (file.size > maxImageSize) {
				onError?.(
					`Image size must be less than ${Math.round(maxImageSize / 1024 / 1024)}MB`,
				);
				return;
			}

			try {
				setImageUploading(true);

				let imageUrl: string;

				if (onImageUpload) {
					imageUrl = await onImageUpload(file);
				} else {
					// Convert to base64 or upload via default method
					imageUrl = await updateProfileImage(URL.createObjectURL(file));
				}

				handleFieldChange("profileImageUrl", imageUrl);
				onSuccess?.("Profile image updated successfully");
			} catch (error) {
				const message =
					error instanceof Error ? error.message : "Failed to upload image";
				onError?.(message);
			} finally {
				setImageUploading(false);
			}
		},
		[
			allowedImageTypes,
			maxImageSize,
			onImageUpload,
			updateProfileImage,
			handleFieldChange,
			onSuccess,
			onError,
		],
	);

	// Handle image removal
	const handleImageRemoval = React.useCallback(async () => {
		try {
			setImageUploading(true);

			if (onImageRemove) {
				await onImageRemove();
			} else {
				await removeProfileImage();
			}

			handleFieldChange("profileImageUrl", "");
			onSuccess?.("Profile image removed successfully");
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "Failed to remove image";
			onError?.(message);
		} finally {
			setImageUploading(false);
		}
	}, [
		onImageRemove,
		removeProfileImage,
		handleFieldChange,
		onSuccess,
		onError,
	]);

	// File input ref
	const fileInputRef = React.useRef<HTMLInputElement>(null);

	// Don't render if no user
	if (!user) {
		return null;
	}

	return (
		<form onSubmit={handleSubmit} className={`space-y-6 ${className}`}>
			{/* Profile Image Section */}
			{showImageUpload && !hideFields.includes("profileImage") && (
				<Card variant={variant}>
					<CardHeader>
						<h4 className="text-md font-semibold">Profile Picture</h4>
					</CardHeader>
					<Divider />
					<CardBody>
						<div className="flex items-center gap-4">
							<Avatar
								src={formData.profileImageUrl}
								name={`${formData.firstName} ${formData.lastName}`}
								size="xl"
								isBordered
								fallback={imageUploading ? <Spinner size="sm" /> : undefined}
							/>

							<div className="flex flex-col gap-2">
								<div className="flex gap-2">
									<Button
										size="sm"
										variant="bordered"
										onPress={() => fileInputRef.current?.click()}
										isDisabled={isDisabled || imageUploading}
										isLoading={imageUploading}
									>
										Upload Photo
									</Button>

									{allowImageRemoval && formData.profileImageUrl && (
										<Button
											size="sm"
											variant="light"
											color="danger"
											onPress={handleImageRemoval}
											isDisabled={isDisabled || imageUploading}
										>
											Remove
										</Button>
									)}
								</div>

								<p className="text-xs text-default-500">
									JPG, PNG or WebP. Max size{" "}
									{Math.round(maxImageSize / 1024 / 1024)}MB.
								</p>
							</div>
						</div>

						<input
							ref={fileInputRef}
							type="file"
							accept={allowedImageTypes.join(",")}
							onChange={(e) => {
								const file = e.target.files?.[0];
								if (file) {
									handleImageUpload(file);
								}
								e.target.value = "";
							}}
							className="hidden"
						/>
					</CardBody>
				</Card>
			)}

			{/* Personal Information */}
			<Card variant={variant}>
				<CardHeader>
					<h4 className="text-md font-semibold">Personal Information</h4>
				</CardHeader>
				<Divider />
				<CardBody>
					<div
						className={`grid gap-4 ${fieldLayout === "double" ? "md:grid-cols-2" : "grid-cols-1"}`}
					>
						{/* First Name */}
						{!hideFields.includes("firstName") && (
							<Input
								label="First Name"
								placeholder="Enter your first name"
								value={formData.firstName}
								onValueChange={(value) => handleFieldChange("firstName", value)}
								variant={variant}
								size={size}
								isDisabled={isDisabled}
								isInvalid={!!errors.firstName}
								errorMessage={errors.firstName}
							/>
						)}

						{/* Last Name */}
						{!hideFields.includes("lastName") && (
							<Input
								label="Last Name"
								placeholder="Enter your last name"
								value={formData.lastName}
								onValueChange={(value) => handleFieldChange("lastName", value)}
								variant={variant}
								size={size}
								isDisabled={isDisabled}
								isInvalid={!!errors.lastName}
								errorMessage={errors.lastName}
							/>
						)}

						{/* Username */}
						{showUsername && !hideFields.includes("username") && (
							<Input
								label="Username"
								placeholder="Enter your username"
								value={formData.username}
								onValueChange={(value) => handleFieldChange("username", value)}
								variant={variant}
								size={size}
								isDisabled={isDisabled}
								isInvalid={!!errors.username}
								errorMessage={errors.username}
							/>
						)}

						{/* Email */}
						{showEmail && !hideFields.includes("email") && (
							<EmailField
								label="Email Address"
								value={formData.email}
								onChange={(value) => handleFieldChange("email", value)}
								variant={variant}
								size={size}
								disabled={isDisabled}
								error={errors.email}
								showVerificationStatus={showVerificationStatus}
								isVerified={isEmailVerified}
							/>
						)}

						{/* Phone */}
						{showPhone && !hideFields.includes("phone") && (
							<PhoneField
								label="Phone Number"
								value={formData.phone}
								onChange={(value) => handleFieldChange("phone", value)}
								variant={variant}
								size={size}
								disabled={isDisabled}
								error={errors.phone}
								showVerificationStatus={showVerificationStatus}
								isVerified={isPhoneVerified}
							/>
						)}
					</div>
				</CardBody>
			</Card>

			{/* Custom Fields */}
			{customFields.length > 0 && (
				<Card variant={variant}>
					<CardHeader>
						<h4 className="text-md font-semibold">Additional Information</h4>
					</CardHeader>
					<Divider />
					<CardBody>
						<div
							className={`grid gap-4 ${fieldLayout === "double" ? "md:grid-cols-2" : "grid-cols-1"}`}
						>
							{customFields.map((field) => {
								const value = formData.customFields?.[field.key] || "";

								switch (field.type) {
									case "textarea":
										return (
											<Textarea
												key={field.key}
												label={field.label}
												placeholder={field.placeholder}
												description={field.description}
												value={value}
												onValueChange={(val) =>
													handleCustomFieldChange(field.key, val)
												}
												variant={variant}
												size={size}
												isDisabled={isDisabled}
												isRequired={field.required}
												isInvalid={!!errors[field.key]}
												errorMessage={errors[field.key]}
											/>
										);

									case "select":
										return (
											<Select
												key={field.key}
												label={field.label}
												placeholder={field.placeholder}
												description={field.description}
												selectedKeys={value ? [value] : []}
												onSelectionChange={(keys) => {
													const selectedValue = Array.from(keys)[0] as string;
													handleCustomFieldChange(field.key, selectedValue);
												}}
												variant={variant}
												size={size}
												isDisabled={isDisabled}
												isRequired={field.required}
												isInvalid={!!errors[field.key]}
												errorMessage={errors[field.key]}
											>
												{field.options?.map((option) => (
													<SelectItem key={option.value} value={option.value}>
														{option.label}
													</SelectItem>
												)) || []}
											</Select>
										);

									case "switch":
										return (
											<div
												key={field.key}
												className="flex items-center justify-between"
											>
												<div>
													<label className="text-sm font-medium">
														{field.label}
														{field.required && (
															<span className="text-danger ml-1">*</span>
														)}
													</label>
													{field.description && (
														<p className="text-xs text-default-500 mt-1">
															{field.description}
														</p>
													)}
												</div>
												<Switch
													isSelected={!!value}
													onValueChange={(checked) =>
														handleCustomFieldChange(field.key, checked)
													}
													size={size}
													isDisabled={isDisabled}
												/>
											</div>
										);

									default:
										return (
											<Input
												key={field.key}
												label={field.label}
												placeholder={field.placeholder}
												description={field.description}
												value={value}
												onValueChange={(val) =>
													handleCustomFieldChange(field.key, val)
												}
												type={field.type}
												variant={variant}
												size={size}
												isDisabled={isDisabled}
												isRequired={field.required}
												isInvalid={!!errors[field.key]}
												errorMessage={errors[field.key]}
											/>
										);
								}
							})}
						</div>
					</CardBody>
				</Card>
			)}

			{/* Save Button */}
			{showSaveButton && !autoSave && (
				<div className="flex justify-end gap-3">
					<Button
						type="submit"
						color="primary"
						isDisabled={isDisabled || !isDirty}
						isLoading={isLoading}
					>
						Save Changes
					</Button>
				</div>
			)}

			{/* Auto-save indicator */}
			{autoSave && isDirty && (
				<div className="flex items-center gap-2 text-sm text-default-500">
					<Spinner size="sm" />
					<span>Auto-saving...</span>
				</div>
			)}
		</form>
	);
}

// ============================================================================
// Export
// ============================================================================

export default ProfileForm;
