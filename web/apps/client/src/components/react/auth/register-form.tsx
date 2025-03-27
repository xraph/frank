"use client";

import type React from "react";
import { useState } from "react";
import { Link } from "../link.tsx";
import { Eye, EyeOff, Github, Mail } from "lucide-react";
import { Button } from "@/components/react/ui/button";
import { Input } from "@/components/react/ui/input";
import { Label } from "@/components/react/ui/label";
import { Separator } from "@/components/react/ui/separator";
import { Checkbox } from "@/components/react/ui/checkbox";
import {
	Form,
	FormControl,
	FormField,
	FormItem,
	FormLabel,
} from "@/components/react/ui/form.tsx";
import { useForm } from "react-hook-form";
import { FrankUIKit } from "@frank-auth/react";

export function RegisterForm() {
	const [error, setError] = useState<string | null>(null);
	const form = useForm();
	const [isLoading, setIsLoading] = useState(false);
	const [showPassword, setShowPassword] = useState(false);

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);

		// Simulate registration
		setTimeout(() => {
			setIsLoading(false);
		}, 1500);
	}

	return (
		<FrankUIKit
			initialView="signup"
			title="Create an account"
			description="Enter your information to get started"
			showTabs={false}
		/>
	);

	return (
		<Form {...form}>
			<div className="space-y-6">
				<form onSubmit={onSubmit} className="space-y-4">
					<div className="grid grid-cols-2 gap-4">
						<FormField
							control={form.control}
							name="firstName"
							render={({ field }) => (
								<FormItem>
									<FormLabel htmlFor="first-name">First name</FormLabel>
									<FormControl>
										<Input
											id="first-name"
											placeholder="John"
											required
											disabled={isLoading}
											{...field}
										/>
									</FormControl>
								</FormItem>
							)}
						/>
						<FormField
							control={form.control}
							name="lastName"
							render={({ field }) => (
								<FormItem>
									<FormLabel htmlFor="last-name">Last name</FormLabel>
									<FormControl>
										<Input
											id="last-name"
											placeholder="Doe"
											required
											disabled={isLoading}
											{...field}
										/>
									</FormControl>
								</FormItem>
							)}
						/>
					</div>
					<FormField
						control={form.control}
						name="email"
						render={({ field }) => (
							<FormItem>
								<FormLabel htmlFor="email">Email</FormLabel>
								<FormControl>
									<Input
										id="email"
										type="email"
										placeholder="name@example.com"
										required
										disabled={isLoading}
										{...field}
									/>
								</FormControl>
							</FormItem>
						)}
					/>
					<FormField
						control={form.control}
						name="password"
						render={({ field }) => (
							<FormItem>
								<FormLabel htmlFor="password">Password</FormLabel>
								<FormControl>
									<div className="relative">
										<Input
											id="password"
											type={showPassword ? "text" : "password"}
											placeholder="••••••••"
											required
											disabled={isLoading}
											{...field}
										/>
										<Button
											type="button"
											variant="ghost"
											size="icon"
											className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
											onClick={() => setShowPassword(!showPassword)}
											disabled={isLoading}
										>
											{showPassword ? (
												<EyeOff className="h-4 w-4 text-muted-foreground" />
											) : (
												<Eye className="h-4 w-4 text-muted-foreground" />
											)}
											<span className="sr-only">
												{showPassword ? "Hide password" : "Show password"}
											</span>
										</Button>
									</div>
								</FormControl>
							</FormItem>
						)}
					/>
					<div className="flex items-center space-x-2">
						<Checkbox id="terms" required />
						<Label htmlFor="terms" className="text-sm font-normal">
							I agree to the{" "}
							<Link
								href="/legal/terms"
								className="text-primary hover:underline"
							>
								Terms of Service
							</Link>{" "}
							and{" "}
							<Link
								href="/legal/privacy"
								className="text-primary hover:underline"
							>
								Privacy Policy
							</Link>
						</Label>
					</div>
					<Button type="submit" className="w-full" disabled={isLoading}>
						{isLoading ? "Creating account..." : "Create account"}
					</Button>
				</form>

				<div className="relative">
					<div className="absolute inset-0 flex items-center">
						<Separator className="w-full" />
					</div>
					<div className="relative flex justify-center text-xs uppercase">
						<span className="bg-background px-2 text-muted-foreground">
							Or continue with
						</span>
					</div>
				</div>

				<div className="grid grid-cols-2 gap-4">
					<Button variant="outline" disabled={isLoading}>
						<Github className="mr-2 h-4 w-4" />
						GitHub
					</Button>
					<Button variant="outline" disabled={isLoading}>
						<Mail className="mr-2 h-4 w-4" />
						Google
					</Button>
				</div>

				<div className="text-center text-sm">
					Already have an account?{" "}
					<Link href="/login" className="text-primary hover:underline">
						Sign in
					</Link>
				</div>
			</div>
		</Form>
	);
}
