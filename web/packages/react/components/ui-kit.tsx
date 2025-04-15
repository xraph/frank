"use client";
import "./styles/globals.css";

import React, {useEffect, useMemo, useRef, useState} from "react";
import {AlertCircle, ArrowLeft, CheckCircle2, Eye, EyeOff, Fingerprint, Key, Mail, RefreshCw,} from "lucide-react";
import {Button} from "@/components/ui/button";
import {Card, CardContent, CardDescription, CardHeader, CardTitle,} from "@/components/ui/card";
import {Input} from "@/components/ui/input";
import {Label} from "@/components/ui/label";
import {Tabs, TabsContent, TabsList, TabsTrigger} from "@/components/ui/tabs";
import {Separator} from "@/components/ui/separator";
import {Checkbox} from "@/components/ui/checkbox";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue,} from "@/components/ui/select";
import {AuthView, FormField, FrankConfig, Link} from "./context";
import {useFrank} from "./hooks";
import {cn} from "@/lib/utils";
import {authLogin} from "@frank-auth/sdk";
import {Alert, AlertDescription, AlertTitle} from "@/components/ui/alert";
import {InputOTP, InputOTPGroup, InputOTPSlot,} from "@/components/ui/input-otp";
import {REGEXP_ONLY_DIGITS_AND_CHARS} from "input-otp";

interface FrankProps extends FrankConfig {
	useProviderConfig?: boolean;
}

export function FrankUIKit({
	logo,
	title,
	titleAlign,
	description,
	oauthProviders,
	onLogin,
	onSignup,
	onPasswordless,
	onPasskey,
	onMfa,
	onForgotPassword,
	onVerifyOtp,
	onResendVerification,
	supportedMethods,
	showTabs,
	availableTabs,
	initialView,
	signupFields,
	theme,
	links,
	verification,
	useProviderConfig = true,
}: FrankProps) {
	// Get configuration from context if useProviderConfig is true
	const { config: providerConfig, ...frank } = useFrank();

	// Merge the provider config with props, prioritizing props
	const config = useProviderConfig
		? {
				// Start with provider config as the base
				...providerConfig,
				// Override with any directly provided props that aren't undefined
				...(logo !== undefined && { logo }),
				...(title !== undefined && { title }),
				...(titleAlign !== undefined && { titleAlign }),
				...(description !== undefined && { description }),
				...(oauthProviders !== undefined && { oauthProviders }),
				...(onLogin !== undefined && { onLogin }),
				...(onSignup !== undefined && { onSignup }),
				...(onPasswordless !== undefined && { onPasswordless }),
				...(onResendVerification !== undefined && { onResendVerification }),
				...(onPasskey !== undefined && { onPasskey }),
				...(onMfa !== undefined && { onMfa }),
				...(onForgotPassword !== undefined && { onForgotPassword }),
				...(onVerifyOtp !== undefined && { onVerifyOtp }),
				...(supportedMethods !== undefined && { supportedMethods }),
				...(showTabs !== undefined && { showTabs }),
				...(availableTabs !== undefined && { availableTabs }),
				...(initialView !== undefined && { initialView }),
				...(signupFields !== undefined && { signupFields }),
				...(theme !== undefined && { theme }),
				...(links !== undefined && { links }),
				...(verification !== undefined && { verification }),
			}
		: {
				// If not using provider config, just use the props directly
				logo,
				title,
				titleAlign,
				description,
				oauthProviders,
				onLogin,
				onSignup,
				onPasswordless,
				onPasskey,
				onMfa,
				onForgotPassword,
				onVerifyOtp,
				supportedMethods,
				showTabs,
				availableTabs,
				initialView,
				signupFields,
				theme,
				links,
				verification,
			};

	// Set default values for required props (rest of the component remains the same)
	const {
		logo: configLogo = <Key className="h-6 w-6" />,
		title: configTitle = "Welcome Back",
		titleAlign: configTitleAlign = "center",
		description: configDescription = "Sign in to your account",
		oauthProviders: configOauthProviders = [],
		onLogin: configOnLogin,
		onSignup: configOnSignup,
		onPasswordless: configOnPasswordless,
		onPasskey: configOnPasskey,
		onMfa: configOnMfa,
		onForgotPassword: configOnForgotPassword,
		onVerifyOtp: configOnVerifyOtp,
		onResendVerification: configOnResendVerification,
		supportedMethods: configSupportedMethods = [
			"password",
			"passwordless",
			"passkey",
		],
		showTabs: configShowTabs = true,
		availableTabs: configAvailableTabs = ["login", "signup"],
		initialView: configInitialView = "login",
		signupFields: configSignupFields = [
			{
				name: "name",
				label: "Name",
				type: "text",
				placeholder: "John Doe",
				required: true,
				row: 1,
				width: "half",
			},
			{
				name: "name",
				label: "Name",
				type: "text",
				placeholder: "John Doe",
				required: true,
				row: 1,
				width: "half",
			},
			{
				name: "email",
				label: "Email",
				type: "email",
				placeholder: "name@example.com",
				required: true,
			},
			{ name: "password", label: "Password", type: "password", required: true },
		],
		links: configLinks = {},
		verification: configVerification = {
			input: "otp",
			codeLength: 6,
		},
		theme: configThemeTemp = {
			primaryColor: "bg-primary",
			backgroundColor: "bg-background",
			textColor: "text-foreground",
			borderRadius: "rounded-md",
		},
	} = config;

	const [activeTab, setActiveTab] = useState<"login" | "signup">(
		configAvailableTabs.includes(configInitialView)
			? (configInitialView as "login" | "signup")
			: "login",
	);
	const [error, setError] = useState<string | null>(null);
	const [currentView, setCurrentView] = useState<AuthView>(configInitialView);
	const [loginStep, setLoginStep] = useState<number>(1);
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [showPassword, setShowPassword] = useState(false);
	const [mfaCode, setMfaCode] = useState("");
	const [otpCode, setOtpCode] = useState("");
	// Resend verification cooldown state
	const [cooldownRemaining, setCooldownRemaining] = useState(0);
	const cooldownTimerRef = useRef<NodeJS.Timeout | null>(null);
	// Status messages
	const [success, setSuccess] = useState("");
	const [isLoading, setIsLoading] = useState(false);

	// Dynamic form state for signup
	const [signupFormData, setSignupFormData] = useState<Record<string, any>>(
		() => {
			const initialData: Record<string, any> = {};
			configSignupFields.forEach((field) => {
				initialData[field.name] = field.type === "checkbox" ? false : "";
			});
			return initialData;
		},
	);
	const configTheme = useMemo(() => {
		return frank.getTheme(configThemeTemp);
	}, [configThemeTemp, frank]);

	// Apply theme styles
	const cardClassName = `w-full py-6 max-w-xl  min-w-md mx-auto ${configTheme.borderRadius || "rounded-md"} overflow-hidden`;
	const buttonClassName = `${configTheme.primaryColor || "bg-primary"} ${configTheme.borderRadius || "rounded-md"}`;
	const inputClassName = `${configTheme.borderRadius || "rounded-md"}`;
	const cardStyle = configTheme.backgroundColor
		? { backgroundColor: configTheme.backgroundColor.replace("bg-", "") }
		: {};
	const textStyle = configTheme.textColor
		? { color: configTheme.textColor.replace("text-", "") }
		: {};
	const titleClasses = cn("text-3xl font-bold", {
		"text-center": configTitleAlign === "center",
		"text-left": configTitleAlign === "left",
		"text-right": configTitleAlign === "right",
	});
	const descriptionClasses = cn("text-muted-foreground ", {
		"text-center": configTitleAlign === "center",
		"text-left": configTitleAlign === "left",
		"text-right": configTitleAlign === "right",
	});

	const codeInputLength = useMemo(() => {
		return new Array(configVerification.codeLength ?? 6).fill(0);
	}, [configVerification.codeLength]);

	// Clean up cooldown timer on unmount
	useEffect(() => {
		return () => {
			if (cooldownTimerRef.current) {
				clearInterval(cooldownTimerRef.current);
			}
		};
	}, []);

	const resetState = () => {
		setLoginStep(1);
		setPassword("");
		setMfaCode("");
		setOtpCode("");
		setError(null);
		setSuccess("");
		setShowPassword(false);
	};

	const handleTabChange = (value: string) => {
		setActiveTab(value as "login" | "signup");
		resetState();
		setCurrentView(value as AuthView);
	};

	const handleEmailSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setLoginStep(2);
	};

	const renderAlertMessages = () => (
		<div className="space-y-4 py-2">
			{error && (
				<Alert variant="destructive">
					<AlertCircle className="h-4 w-4" />
					<AlertTitle>Error</AlertTitle>
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			)}

			{success && (
				<Alert
					variant="default"
					className="border-green-500 bg-green-500/10 text-green-500"
				>
					<CheckCircle2 className="h-4 w-4" />
					<AlertTitle>Success</AlertTitle>
					<AlertDescription>{success}</AlertDescription>
				</Alert>
			)}
		</div>
	);

	const handleLogin = async (e: React.FormEvent) => {
		e.preventDefault();

		setIsLoading(true);
		try {
			const rsp = await authLogin({
				body: {
					email,
					password,
					organization_id: config.api?.projectId,
				},
			});

			if (rsp.error) {
				setError(rsp.error.message);
				return;
			}

			await configOnLogin?.({ email, password });
			let href;

			if (rsp.data.requiresVerification) {
				if (links?.verify) {
					href = `${links.verify.url}?email=${email}&${rsp.data.token}`;
					href += `&redirect_url=${window.location.href}`;
					href += `&method=${rsp.data.verificationMethod}`;
					href += `&vid=${rsp.data.verificationId}`;
					window.location.href = href;
				} else {
					setCurrentView("verify-otp");
				}
				return;
			}

			if (rsp.data.message) {
				setSuccess(rsp.data.message);
			}

			if (rsp.data.mfa_required) {
				if (links?.mfa) {
					href = `${links.mfa.url}?email=${email}&${rsp.data.token}`;
					href += `&redirect_url=${window.location.href}`;
					href += `&method=${rsp.data.verificationMethod}`;
					href += `&vid=${rsp.data.verificationId}`;
					window.location.href = href;
				} else {
					setCurrentView("mfa");
				}
				return;
			}
		} catch (error) {
			console.error("Login error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleSignup = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!configOnSignup) return;

		setIsLoading(true);
		try {
			await configOnSignup(signupFormData);
		} catch (error) {
			console.error("Signup error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handlePasswordless = async () => {
		if (!configOnPasswordless) return;

		setIsLoading(true);
		try {
			await configOnPasswordless(email);
		} catch (error) {
			console.error("Passwordless error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handlePasskey = async () => {
		if (!configOnPasskey) return;

		setIsLoading(true);
		try {
			await configOnPasskey();
		} catch (error) {
			console.error("Passkey error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleMfa = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!configOnMfa) return;

		setIsLoading(true);
		try {
			await configOnMfa(mfaCode);
			setCurrentView("login");
			resetState();
		} catch (error) {
			console.error("MFA error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleForgotPassword = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!configOnForgotPassword) return;

		setIsLoading(true);
		try {
			await configOnForgotPassword(email);
			// Optionally navigate to a confirmation screen
		} catch (error) {
			console.error("Forgot password error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleVerifyOtp = async (e: React.FormEvent) => {
		e.preventDefault();
		setIsLoading(true);
		try {
			const rsp = await frank.verifyEmail({
				email,
				otp: otpCode,
				method: "otp",
			});
			configOnVerifyOtp?.(email, otpCode);
			console.log("Verify OTP response:", rsp);
			setCurrentView("login");
			resetState();
		} catch (error) {
			console.error("OTP verification error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleResendVerification = async () => {
		if (cooldownRemaining > 0) return;

		setIsLoading(true);
		try {
			const rsp = await frank.resendVerification({
				email,
				verification_type: "otp"
			})
			
			await configOnResendVerification
				?.(email);

			// Start cooldown timer
			setCooldownRemaining(frank.resendCooldown);

			if (cooldownTimerRef.current) {
				clearInterval(cooldownTimerRef.current);
			}

			cooldownTimerRef.current = setInterval(() => {
				setCooldownRemaining((prev) => {
					if (prev <= 1) {
						if (cooldownTimerRef.current) {
							clearInterval(cooldownTimerRef.current);
							cooldownTimerRef.current = null;
						}
						return 0;
					}
					return prev - 1;
				});
			}, 1000);
		} catch (error) {
			console.error("Resend verification error:", error);
		} finally {
			setIsLoading(false);
		}
	};

	const handleSignupFieldChange = (name: string, value: any) => {
		setSignupFormData((prev) => ({
			...prev,
			[name]: value,
		}));

		// Special case for email field to also update the login email
		if (name === "email") {
			setEmail(value);
		}
	};

	const renderAuthLink = (link: Link) => (
		<div className="text-sm">
			<p className="text-center space-x-2">
				{link.preText && <span>{link.preText} </span>}
				<a
					href={link.url}
					className="underline hover:text-foreground transition-colors"
				>
					{link.text}
				</a>
			</p>
		</div>
	);

	const renderFormFieldContent = (field: FormField) => {
		const { name, label, type, placeholder, required, options, validation } =
			field;
		const value = signupFormData[name];

		switch (type) {
			case "checkbox":
				return (
					<>
						<Checkbox
							id={`signup-${name}`}
							checked={value}
							onCheckedChange={(checked) =>
								handleSignupFieldChange(name, checked)
							}
						/>
						<Label htmlFor={`signup-${name}`}>{label}</Label>
					</>
				);

			case "select":
				return (
					<>
						<Label htmlFor={`signup-${name}`}>{label}</Label>
						<Select
							value={value}
							onValueChange={(newValue) =>
								handleSignupFieldChange(name, newValue)
							}
						>
							<SelectTrigger id={`signup-${name}`} className={inputClassName}>
								<SelectValue placeholder={placeholder || `Select ${label}`} />
							</SelectTrigger>
							<SelectContent>
								{options?.map((option) => (
									<SelectItem key={option.value} value={option.value}>
										{option.label}
									</SelectItem>
								))}
							</SelectContent>
						</Select>
					</>
				);

			case "password":
				return (
					<>
						<Label htmlFor={`signup-${name}`}>{label}</Label>
						<div className="relative">
							<Input
								id={`signup-${name}`}
								type={showPassword ? "text" : "password"}
								placeholder={placeholder}
								value={value}
								onChange={(e) => handleSignupFieldChange(name, e.target.value)}
								required={required}
								className={inputClassName}
								{...(validation && {
									pattern: validation.pattern,
									minLength: validation.minLength,
									maxLength: validation.maxLength,
								})}
							/>
							<Button
								type="button"
								variant="ghost"
								size="icon"
								className="absolute right-0 top-0 h-full px-3"
								onClick={() => setShowPassword(!showPassword)}
							>
								{showPassword ? (
									<EyeOff className="h-4 w-4" />
								) : (
									<Eye className="h-4 w-4" />
								)}
							</Button>
						</div>
					</>
				);

			default:
				return (
					<>
						<Label htmlFor={`signup-${name}`}>{label}</Label>
						<Input
							id={`signup-${name}`}
							type={type}
							placeholder={placeholder}
							value={value}
							onChange={(e) => handleSignupFieldChange(name, e.target.value)}
							required={required}
							className={inputClassName}
							{...(validation && {
								pattern: validation.pattern,
								minLength: validation.minLength,
								maxLength: validation.maxLength,
								min: validation.min,
								max: validation.max,
							})}
						/>
					</>
				);
		}
	};

	const renderFormField = (field: FormField) => {
		const { name, type, width = "full" } = field;

		// Define width classes
		const widthClasses = {
			full: "w-full",
			half: "w-full sm:w-[calc(50%-0.375rem)]", // Accounting for the gap
			third: "w-full sm:w-[calc(33.333%-0.5rem)]", // Accounting for the gap
		};

		// For checkbox type, use a different layout
		if (type === "checkbox") {
			return (
				<div
					className={`flex items-center space-x-2 ${widthClasses[width]}`}
					key={name}
				>
					{renderFormFieldContent(field)}
				</div>
			);
		}

		// For other field types
		return (
			<div className={`grid gap-2 ${widthClasses[width]}`} key={name}>
				{renderFormFieldContent(field)}
			</div>
		);
	};

	const renderSignup = () => {
		// Group fields by row
		const fieldsByRow: Record<string, FormField[]> = {};

		configSignupFields.forEach((field) => {
			const rowKey = field.row?.toString() || "default";
			if (!fieldsByRow[rowKey]) {
				fieldsByRow[rowKey] = [];
			}
			fieldsByRow[rowKey].push(field);
		});

		return (
			<form onSubmit={handleSignup}>
				<div className="grid gap-4">
					{Object.entries(fieldsByRow).map(([rowKey, fields]) => (
						<div
							key={rowKey}
							className="flex flex-wrap w-full gap-3 justify-between"
						>
							{fields.map((field) => renderFormField(field))}
						</div>
					))}

					<Button
						type="submit"
						className={buttonClassName}
						disabled={isLoading}
					>
						{isLoading ? "Creating Account..." : "Create Account"}
					</Button>

					{configLinks?.showAuthLinks &&
						configLinks.login &&
						renderAuthLink(configLinks.login)}

					{(configLinks.legal ?? []).length > 0 && (
						<div className="text-xs text-muted-foreground mt-2">
							<p className="text-center">
								{configLinks.legal?.map((link, index) => (
									<span key={index}>
										{index > 0 && " • "}
										<a
											href={link.url}
											className="underline hover:text-foreground transition-colors"
											target="_blank"
											rel="noopener noreferrer"
										>
											{link.text}
										</a>
									</span>
								))}
							</p>
						</div>
					)}
				</div>
			</form>
		);
	};

	const renderForgotPassword = () => (
		<Card className={cardClassName} style={cardStyle}>
			<CardHeader>
				<div className="flex items-center justify-center mb-4">
					{configLogo}
				</div>
				<CardTitle className={titleClasses} style={textStyle}>
					{configTitle}
				</CardTitle>
				<CardDescription className={descriptionClasses} style={textStyle}>
					Enter your email to receive a password reset link
				</CardDescription>
			</CardHeader>
			<CardContent>
				{renderAlertMessages()}
				<form onSubmit={handleForgotPassword}>
					<div className="grid gap-4">
						<div className="grid gap-2">
							<Label htmlFor="email-reset" style={textStyle}>
								Email
							</Label>
							<Input
								id="email-reset"
								type="email"
								placeholder="name@example.com"
								value={email}
								onChange={(e) => setEmail(e.target.value)}
								required
								className={inputClassName}
							/>
						</div>
						<Button
							type="submit"
							className={buttonClassName}
							disabled={isLoading}
						>
							{isLoading ? "Sending..." : "Send Reset Link"}
						</Button>
						<Button
							variant="outline"
							type="button"
							onClick={() => setCurrentView("login")}
							className={configTheme.borderRadius}
						>
							<ArrowLeft className="mr-2 h-4 w-4" />
							Back to Login
						</Button>
					</div>
				</form>
			</CardContent>
		</Card>
	);

	const renderVerifyOtp = () => (
		<Card className={cardClassName} style={cardStyle}>
			<CardHeader>
				<div className="flex items-center justify-center mb-4">
					{configLogo}
				</div>
				<CardTitle className={titleClasses} style={textStyle}>
					Verification Required
				</CardTitle>
				<CardDescription className={descriptionClasses} style={textStyle}>
					Enter the verification code sent to your device
				</CardDescription>
			</CardHeader>
			<CardContent>
				<form onSubmit={handleVerifyOtp}>
					<div className="grid gap-4">
						<div
							className={cn({
								"grid gap-2": configVerification.input === "input",
								"flex justify-center": configVerification.input === "otp",
							})}
						>
							{configVerification.input === "input" && (
								<>
									<Label htmlFor="otp-code" style={textStyle}>
										Verification Code
									</Label>
									<Input
										id="otp-code"
										placeholder="Enter 6-digit code"
										value={otpCode}
										onChange={(e) => setOtpCode(e.target.value)}
										className={`text-center text-lg tracking-widest ${inputClassName}`}
										maxLength={codeInputLength.length}
									/>
								</>
							)}

							{configVerification.input === "otp" && (
								<InputOTP
									id="otp-code"
									maxLength={codeInputLength.length}
									pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
									value={otpCode}
									required
									onChange={(v) => setOtpCode(v)}
									className={`text-center text-lg tracking-widest ${inputClassName}`}
								>
									<InputOTPGroup>
										{codeInputLength.map((value, idx) => (
											<InputOTPSlot
												index={idx}
												className="size-10 text-xl"
											/>
										))}
									</InputOTPGroup>
								</InputOTP>
							)}
						</div>
						<Button
							type="submit"
							className={buttonClassName}
							disabled={isLoading}
						>
							{isLoading ? "Verifying..." : "Verify"}
						</Button>

						<div className="text-center mt-2">
							<Button
								variant="link"
								type="button"
								onClick={handleResendVerification}
								disabled={cooldownRemaining > 0 || isLoading}
								className="p-0 h-auto flex items-center justify-center mx-auto"
							>
								<RefreshCw className="mr-2 h-3 w-3" />
								{cooldownRemaining > 0
									? `Resend code (${cooldownRemaining}s)`
									: "Resend verification code"}
							</Button>
						</div>

						<Button
							variant="outline"
							type="button"
							onClick={() => {
								setCurrentView("login");
								resetState();
							}}
							className={configTheme.borderRadius}
						>
							<ArrowLeft className="mr-2 h-4 w-4" />
							Back to Login
						</Button>
					</div>
				</form>
			</CardContent>
		</Card>
	);

	const renderMfa = () => (
		<Card className={cardClassName} style={cardStyle}>
			<CardHeader>
				<div className="flex items-center justify-center mb-4">
					{configLogo}
				</div>
				<CardTitle className={titleClasses} style={textStyle}>
					Two-Factor Authentication
				</CardTitle>
				<CardDescription className={descriptionClasses} style={textStyle}>
					Enter the verification code sent to your device
				</CardDescription>
			</CardHeader>
			<CardContent>
				<form onSubmit={handleMfa}>
					<div className="grid gap-4">
						<div className="grid gap-2">
							<Label htmlFor="mfa-code" style={textStyle}>
								Verification Code
							</Label>
							<Input
								id="mfa-code"
								placeholder="Enter 6-digit code"
								value={mfaCode}
								onChange={(e) => setMfaCode(e.target.value)}
								className={`text-center text-lg tracking-widest ${inputClassName}`}
								maxLength={6}
							/>
						</div>
						<Button
							type="submit"
							className={buttonClassName}
							disabled={isLoading}
						>
							{isLoading ? "Verifying..." : "Verify"}
						</Button>
						<Button
							variant="outline"
							type="button"
							onClick={() => {
								setCurrentView("login");
								resetState();
							}}
							className={configTheme.borderRadius}
						>
							<ArrowLeft className="mr-2 h-4 w-4" />
							Back to Login
						</Button>
					</div>
				</form>
			</CardContent>
		</Card>
	);

	const renderLoginStep1 = () => (
		<form onSubmit={handleEmailSubmit}>
			<div className="grid gap-4">
				<div className="grid gap-2">
					<Label htmlFor="email" style={textStyle}>
						Email
					</Label>
					<Input
						id="email"
						type="email"
						placeholder="name@example.com"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						required
						className={inputClassName}
					/>
				</div>
				<Button type="submit" className={buttonClassName}>
					Continue
				</Button>
				{configLinks?.showAuthLinks &&
					configLinks.signup &&
					renderAuthLink(configLinks.signup)}

				{/*<div className="text-center">*/}
				{/*	<Button*/}
				{/*		variant="link"*/}
				{/*		type="button"*/}
				{/*		onClick={() => setCurrentView("forgot-password")}*/}
				{/*		className="p-0 h-auto"*/}
				{/*	>*/}
				{/*		Forgot password?*/}
				{/*	</Button>*/}
				{/*</div>*/}
			</div>
		</form>
	);

	const renderLoginStep2 = () => (
		<>
			<div className="mb-4">
				<Button
					variant="ghost"
					type="button"
					onClick={() => setLoginStep(1)}
					className="p-0 h-auto flex items-center text-muted-foreground hover:text-foreground"
				>
					<ArrowLeft className="mr-2 h-4 w-4" />
					{email}
				</Button>
			</div>

			{renderAlertMessages()}

			<div className="grid gap-4">
				{configSupportedMethods.includes("password") && (
					<form onSubmit={handleLogin}>
						<div className="grid gap-4">
							<div className="grid gap-2">
								<div className="flex items-center justify-between">
									<Label htmlFor="password" style={textStyle}>
										Password
									</Label>
									{configLinks?.forgotPassword ? (
										<a
											href={configLinks.forgotPassword.url}
											className="text-sm text-primary hover:underline"
										>
											{configLinks.forgotPassword.text}
										</a>
									) : (
										<Button
											variant="link"
											type="button"
											onClick={() => setCurrentView("forgot-password")}
											className="p-0 h-auto"
										>
											Forgot password?
										</Button>
									)}
								</div>
								<div className="relative">
									<Input
										id="password"
										type={showPassword ? "text" : "password"}
										value={password}
										onChange={(e) => setPassword(e.target.value)}
										required
										className={inputClassName}
									/>
									<Button
										type="button"
										variant="ghost"
										size="icon"
										className="absolute right-0 top-0 h-full px-3"
										onClick={() => setShowPassword(!showPassword)}
									>
										{showPassword ? (
											<EyeOff className="h-4 w-4" />
										) : (
											<Eye className="h-4 w-4" />
										)}
									</Button>
								</div>
							</div>
							<Button
								type="submit"
								className={buttonClassName}
								disabled={isLoading}
							>
								{isLoading ? "Signing in..." : "Sign in"}
							</Button>
						</div>
					</form>
				)}

				{configSupportedMethods.includes("passwordless") && (
					<Button
						variant="outline"
						onClick={handlePasswordless}
						disabled={isLoading}
						className={configTheme.borderRadius}
					>
						<Mail className="mr-2 h-4 w-4" />
						{isLoading ? "Sending..." : "Sign in with Email Link"}
					</Button>
				)}

				{configSupportedMethods.includes("passkey") && (
					<Button
						variant="outline"
						onClick={handlePasskey}
						disabled={isLoading}
						className={configTheme.borderRadius}
					>
						<Fingerprint className="mr-2 h-4 w-4" />
						{isLoading ? "Authenticating..." : "Sign in with Passkey"}
					</Button>
				)}
			</div>

			{configOauthProviders.length > 0 && (
				<>
					<div className="relative my-4">
						<div className="absolute inset-0 flex items-center">
							<Separator />
						</div>
						<div className="relative flex justify-center text-xs uppercase">
							<span
								className="bg-background px-2 text-muted-foreground"
								style={textStyle}
							>
								Or continue with
							</span>
						</div>
					</div>

					<div className="grid gap-2">
						{configOauthProviders.map((provider, index) => (
							<Button
								key={index}
								variant="outline"
								onClick={provider.onClick}
								className={configTheme.borderRadius}
							>
								{provider.icon}
								<span className="ml-2">{provider.name}</span>
							</Button>
						))}
					</div>
				</>
			)}
		</>
	);

	// Render different views based on currentView state
	if (currentView === "forgot-password") {
		return renderForgotPassword();
	}

	if (currentView === "verify-otp") {
		return renderVerifyOtp();
	}

	if (currentView === "mfa") {
		return renderMfa();
	}

	return (
		<Card className={cardClassName} style={cardStyle}>
			<CardHeader>
				<div
					className={cn("flex mb-4 items-center", {
						"justify-center": configTitleAlign === "center",
						"justify-start": configTitleAlign === "left",
						"justify-end": configTitleAlign === "right",
					})}
				>
					{configLogo}
				</div>
				<CardTitle className={titleClasses} style={textStyle}>
					{configTitle}
				</CardTitle>
				<CardDescription className={descriptionClasses} style={textStyle}>
					{configDescription}
				</CardDescription>
			</CardHeader>
			<CardContent>
				{configShowTabs && configAvailableTabs.length > 1 ? (
					<Tabs
						defaultValue={activeTab}
						value={activeTab}
						onValueChange={handleTabChange}
					>
						<TabsList
							className={`grid w-full ${configTheme.borderRadius}`}
							style={{
								gridTemplateColumns: `repeat(${configAvailableTabs.length}, 1fr)`,
							}}
						>
							{configAvailableTabs.includes("login") && (
								<TabsTrigger value="login">Login</TabsTrigger>
							)}
							{configAvailableTabs.includes("signup") && (
								<TabsTrigger value="signup">Sign Up</TabsTrigger>
							)}
						</TabsList>
						{configAvailableTabs.includes("login") && (
							<TabsContent value="login" className="mt-4">
								{loginStep === 1 ? renderLoginStep1() : renderLoginStep2()}
							</TabsContent>
						)}
						{configAvailableTabs.includes("signup") && (
							<TabsContent value="signup" className="mt-4">
								{renderSignup()}
							</TabsContent>
						)}
					</Tabs>
				) : (
					<div className="mt-4">
						{activeTab === "login"
							? loginStep === 1
								? renderLoginStep1()
								: renderLoginStep2()
							: renderSignup()}
					</div>
				)}
			</CardContent>
		</Card>
	);
}
