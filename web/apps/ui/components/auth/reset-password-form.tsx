"use client";

import type React from "react";
import { useState } from "react";
import { Link } from "../link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, ArrowLeft, CheckCircle2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function ResetPasswordForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [isSubmitted, setIsSubmitted] = useState(false);
	const [error, setError] = useState("");

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);
		setError("");

		// Simulate password reset request
		setTimeout(() => {
			setIsLoading(false);
			setIsSubmitted(true);
		}, 1500);
	}

	if (isSubmitted) {
		return (
			<div className="space-y-6">
				<Alert
					variant="default"
					className="border-green-500 bg-green-500/10 text-green-500"
				>
					<CheckCircle2 className="h-4 w-4" />
					<AlertTitle>Check your email</AlertTitle>
					<AlertDescription>
						We&apos;ve sent you a password reset link. Please check your inbox.
					</AlertDescription>
				</Alert>
				<Button asChild variant="outline" className="w-full">
					<Link href="/auth/login">
						<ArrowLeft className="mr-2 h-4 w-4" />
						Back to login
					</Link>
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

			<form onSubmit={onSubmit} className="space-y-4">
				<div className="space-y-2">
					<Label htmlFor="email">Email</Label>
					<Input
						id="email"
						type="email"
						placeholder="name@example.com"
						required
						disabled={isLoading}
					/>
				</div>
				<Button type="submit" className="w-full" disabled={isLoading}>
					{isLoading ? "Sending reset link..." : "Send reset link"}
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
