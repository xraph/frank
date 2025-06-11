"use client";

import type React from "react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Eye, EyeOff } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function PasswordForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [success, setSuccess] = useState("");
	const [error, setError] = useState("");
	const [showCurrentPassword, setShowCurrentPassword] = useState(false);
	const [showNewPassword, setShowNewPassword] = useState(false);
	const [showConfirmPassword, setShowConfirmPassword] = useState(false);

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);
		setError("");
		setSuccess("");

		// Simulate password update
		setTimeout(() => {
			setIsLoading(false);
			setSuccess("Your password has been updated successfully.");
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

			<form onSubmit={onSubmit} className="space-y-6">
				<Card>
					<CardContent className="p-6 space-y-4">
						<div className="space-y-2">
							<Label htmlFor="current-password">Current password</Label>
							<div className="relative">
								<Input
									id="current-password"
									type={showCurrentPassword ? "text" : "password"}
									placeholder="••••••••"
									required
									disabled={isLoading}
								/>
								<Button
									type="button"
									variant="ghost"
									size="icon"
									className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
									onClick={() => setShowCurrentPassword(!showCurrentPassword)}
									disabled={isLoading}
								>
									{showCurrentPassword ? (
										<EyeOff className="h-4 w-4 text-muted-foreground" />
									) : (
										<Eye className="h-4 w-4 text-muted-foreground" />
									)}
									<span className="sr-only">
										{showCurrentPassword ? "Hide password" : "Show password"}
									</span>
								</Button>
							</div>
						</div>

						<div className="space-y-2">
							<Label htmlFor="new-password">New password</Label>
							<div className="relative">
								<Input
									id="new-password"
									type={showNewPassword ? "text" : "password"}
									placeholder="••••••••"
									required
									disabled={isLoading}
								/>
								<Button
									type="button"
									variant="ghost"
									size="icon"
									className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
									onClick={() => setShowNewPassword(!showNewPassword)}
									disabled={isLoading}
								>
									{showNewPassword ? (
										<EyeOff className="h-4 w-4 text-muted-foreground" />
									) : (
										<Eye className="h-4 w-4 text-muted-foreground" />
									)}
									<span className="sr-only">
										{showNewPassword ? "Hide password" : "Show password"}
									</span>
								</Button>
							</div>
							<p className="text-xs text-muted-foreground">
								Password must be at least 8 characters long and include a mix of
								letters, numbers, and symbols.
							</p>
						</div>

						<div className="space-y-2">
							<Label htmlFor="confirm-password">Confirm new password</Label>
							<div className="relative">
								<Input
									id="confirm-password"
									type={showConfirmPassword ? "text" : "password"}
									placeholder="••••••••"
									required
									disabled={isLoading}
								/>
								<Button
									type="button"
									variant="ghost"
									size="icon"
									className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
									onClick={() => setShowConfirmPassword(!showConfirmPassword)}
									disabled={isLoading}
								>
									{showConfirmPassword ? (
										<EyeOff className="h-4 w-4 text-muted-foreground" />
									) : (
										<Eye className="h-4 w-4 text-muted-foreground" />
									)}
									<span className="sr-only">
										{showConfirmPassword ? "Hide password" : "Show password"}
									</span>
								</Button>
							</div>
						</div>
					</CardContent>
				</Card>

				<div className="flex justify-end">
					<Button type="submit" disabled={isLoading}>
						{isLoading ? "Updating..." : "Update password"}
					</Button>
				</div>
			</form>
		</div>
	);
}
