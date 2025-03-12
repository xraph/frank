"use client";

import type React from "react";

import { useState } from "react";
import { Link } from "./link";
import { Button } from "@/components/react/ui/button";
import { Label } from "@/components/react/ui/label";
import { AlertCircle, ArrowLeft, CheckCircle2 } from "lucide-react";
import {
	Alert,
	AlertDescription,
	AlertTitle,
} from "@/components/react/ui/alert";
import {InputOTP, InputOTPSeparator, InputOTPGroup, InputOTPSlot} from "@/components/react/ui/input-otp.tsx";

const inputClass = "h-12 w-12 text-center text-lg";

export function VerifyEmailForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [isVerified, setIsVerified] = useState(false);
	const [error, setError] = useState("");
	const [code, setCode] = useState('');

	function handleCodeChange(value: string) {
		setCode(value);
	}

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);
		setError("");

		// Simulate verification
		setTimeout(() => {
			setIsLoading(false);
			setIsVerified(true);
		}, 1500);
	}

	if (isVerified) {
		return (
			<div className="space-y-6">
				<Alert
					variant="default"
					className="border-green-500 bg-green-500/10 text-green-500"
				>
					<CheckCircle2 className="h-4 w-4" />
					<AlertTitle>Email verified</AlertTitle>
					<AlertDescription>
						Your email has been successfully verified. You can now access your
						account.
					</AlertDescription>
				</Alert>
				<Button asChild className="w-full">
					<Link href="/auth/login">Continue to login</Link>
				</Button>
			</div>
		);
	}

	return (
		<div className="space-y-6">
			{error && (
				<Alert variant="destructive">
					<AlertCircle className="h-4 w-4" />
					<AlertTitle>Error</AlertTitle>
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			)}

			<form onSubmit={onSubmit} className="space-y-4 justify-center flex flex-col items-center">
				<div className="space-y-2">
					<Label htmlFor="code-0">Verification code</Label>
					<InputOTP
					maxLength={6}
					value={code}
					onChange={handleCodeChange}
					disabled={isLoading}
				>
					<InputOTPGroup>
						<InputOTPSlot className={inputClass} index={0} />
						<InputOTPSlot className={inputClass} index={1} />
						<InputOTPSlot className={inputClass} index={2} />
					</InputOTPGroup>
					<InputOTPSeparator />
					<InputOTPGroup>
						<InputOTPSlot className={inputClass} index={3} />
						<InputOTPSlot className={inputClass} index={4} />
						<InputOTPSlot className={inputClass} index={5} />
					</InputOTPGroup>
				</InputOTP>
				</div>
				<Button
					type="submit"
					className="w-full"
					disabled={isLoading || code.length < 6}
				>
					{isLoading ? "Verifying..." : "Verify email"}
				</Button>
			</form>

			<div className="text-center text-sm">
				<p className="text-muted-foreground mb-2">
					Didn&apos;t receive a code?{" "}
					<Button variant="link" className="p-0 h-auto" disabled={isLoading}>
						Resend code
					</Button>
				</p>
				<Link href="/auth/login" className="text-primary hover:underline">
					<ArrowLeft className="mr-2 h-4 w-4 inline" />
					Back to login
				</Link>
			</div>
		</div>
	);
}
