"use client";

import type React from "react";

import { useState } from "react";
import { Button } from "@/components/react/ui/button";
import { Input } from "@/components/react/ui/input";
import { Label } from "@/components/react/ui/label";
import {
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "@/components/react/ui/tabs";
import {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "@/components/react/ui/card";
import {
	Avatar,
	AvatarFallback,
	AvatarImage,
} from "@/components/react/ui/avatar";
import { AlertCircle, CheckCircle2, Upload } from "lucide-react";
import {
	Alert,
	AlertDescription,
	AlertTitle,
} from "@/components/react/ui/alert";
import { Switch } from "@/components/react/ui/switch";

export function ProfileForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [success, setSuccess] = useState("");
	const [error, setError] = useState("");

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);
		setError("");
		setSuccess("");

		// Simulate profile update
		setTimeout(() => {
			setIsLoading(false);
			setSuccess("Your profile has been updated successfully.");
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

			<Tabs defaultValue="profile" className="w-full">
				<TabsList className="grid w-full grid-cols-3">
					<TabsTrigger value="profile">Profile</TabsTrigger>
					<TabsTrigger value="security">Security</TabsTrigger>
					<TabsTrigger value="preferences">Preferences</TabsTrigger>
				</TabsList>

				<TabsContent value="profile" className="space-y-4 mt-4">
					<Card>
						<CardHeader>
							<CardTitle>Profile Information</CardTitle>
							<CardDescription>
								Update your profile information and avatar
							</CardDescription>
						</CardHeader>
						<form onSubmit={onSubmit}>
							<CardContent className="space-y-4">
								<div className="flex flex-col items-center space-y-2">
									<Avatar className="h-24 w-24">
										<AvatarImage
											src="/placeholder.svg?height=96&width=96"
											alt="Avatar"
										/>
										<AvatarFallback>JD</AvatarFallback>
									</Avatar>
									<Button type="button" variant="outline" size="sm">
										<Upload className="mr-2 h-4 w-4" />
										Change avatar
									</Button>
								</div>

								<div className="grid grid-cols-2 gap-4">
									<div className="space-y-2">
										<Label htmlFor="first-name">First name</Label>
										<Input
											id="first-name"
											defaultValue="John"
											disabled={isLoading}
										/>
									</div>
									<div className="space-y-2">
										<Label htmlFor="last-name">Last name</Label>
										<Input
											id="last-name"
											defaultValue="Doe"
											disabled={isLoading}
										/>
									</div>
								</div>

								<div className="space-y-2">
									<Label htmlFor="email">Email</Label>
									<Input
										id="email"
										type="email"
										defaultValue="john.doe@example.com"
										disabled
									/>
									<p className="text-xs text-muted-foreground">
										Your email cannot be changed
									</p>
								</div>
							</CardContent>
							<CardFooter>
								<Button type="submit" disabled={isLoading}>
									{isLoading ? "Saving..." : "Save changes"}
								</Button>
							</CardFooter>
						</form>
					</Card>
				</TabsContent>

				<TabsContent value="security" className="space-y-4 mt-4">
					<Card>
						<CardHeader>
							<CardTitle>Change Password</CardTitle>
							<CardDescription>
								Update your password to keep your account secure
							</CardDescription>
						</CardHeader>
						<form onSubmit={onSubmit}>
							<CardContent className="space-y-4">
								<div className="space-y-2">
									<Label htmlFor="current-password">Current password</Label>
									<Input
										id="current-password"
										type="password"
										placeholder="••••••••"
										required
										disabled={isLoading}
									/>
								</div>
								<div className="space-y-2">
									<Label htmlFor="new-password">New password</Label>
									<Input
										id="new-password"
										type="password"
										placeholder="••••••••"
										required
										disabled={isLoading}
									/>
								</div>
								<div className="space-y-2">
									<Label htmlFor="confirm-password">Confirm new password</Label>
									<Input
										id="confirm-password"
										type="password"
										placeholder="••••••••"
										required
										disabled={isLoading}
									/>
								</div>
							</CardContent>
							<CardFooter>
								<Button type="submit" disabled={isLoading}>
									{isLoading ? "Updating..." : "Update password"}
								</Button>
							</CardFooter>
						</form>
					</Card>

					<Card>
						<CardHeader>
							<CardTitle>Two-Factor Authentication</CardTitle>
							<CardDescription>
								Add an extra layer of security to your account
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4">
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<h4 className="font-medium">Authenticator app</h4>
									<p className="text-sm text-muted-foreground">
										Use an authenticator app to get two-factor authentication
										codes
									</p>
								</div>
								<Switch defaultChecked={false} />
							</div>
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<h4 className="font-medium">SMS authentication</h4>
									<p className="text-sm text-muted-foreground">
										Receive a code via SMS to verify your identity
									</p>
								</div>
								<Switch defaultChecked={false} />
							</div>
						</CardContent>
					</Card>
				</TabsContent>

				<TabsContent value="preferences" className="space-y-4 mt-4">
					<Card>
						<CardHeader>
							<CardTitle>Notification Preferences</CardTitle>
							<CardDescription>
								Manage how you receive notifications
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4">
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<h4 className="font-medium">Email notifications</h4>
									<p className="text-sm text-muted-foreground">
										Receive email notifications about account activity
									</p>
								</div>
								<Switch defaultChecked={true} />
							</div>
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<h4 className="font-medium">Marketing emails</h4>
									<p className="text-sm text-muted-foreground">
										Receive marketing and promotional emails
									</p>
								</div>
								<Switch defaultChecked={false} />
							</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader>
							<CardTitle>Appearance</CardTitle>
							<CardDescription>
								Customize how the application looks
							</CardDescription>
						</CardHeader>
						<CardContent>
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<h4 className="font-medium">Dark mode</h4>
									<p className="text-sm text-muted-foreground">
										Toggle between light and dark mode
									</p>
								</div>
								<Switch defaultChecked={true} />
							</div>
						</CardContent>
					</Card>
				</TabsContent>
			</Tabs>
		</div>
	);
}
