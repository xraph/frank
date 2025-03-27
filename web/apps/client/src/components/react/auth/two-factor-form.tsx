"use client";

import type React from "react";
import { useState } from "react";
import { Link } from "../link.tsx";
import { Button } from "@/components/react/ui/button";
import { Label } from "@/components/react/ui/label";
import { AlertCircle, ArrowLeft } from "lucide-react";
import {
	Alert,
	AlertDescription,
	AlertTitle,
} from "@/components/react/ui/alert";
import {
	InputOTP,
	InputOTPGroup,
	InputOTPSeparator,
	InputOTPSlot,
} from "@/components/react/ui/input-otp.tsx";

const inputClass = "h-12 w-12 text-center text-lg";

export function TwoFactorForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState("");
	const [code, setCode] = useState("");

	function handleCodeChange(value: string) {
		setCode(value);
	}

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);
		setError("");

		// Simulate 2FA verification
		setTimeout(() => {
			setIsLoading(false);
			// Redirect would happen here in a real app
		}, 1500);
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

			<form
				onSubmit={onSubmit}
				className="space-y-4 justify-center flex flex-col items-center"
			>
				<div className="space-y-2">
					<Label htmlFor="2fa-0">Authentication code</Label>
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
					{isLoading ? "Verifying..." : "Verify"}
				</Button>
			</form>

			<div className="text-center text-sm">
				<Link href="/auth/login" className="text-primary hover:underline">
					<ArrowLeft className="mr-2 h-4 w-4 inline" />
					Back to login
				</Link>
			</div>
		</div>
	);
}
