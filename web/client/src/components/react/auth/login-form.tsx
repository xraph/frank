"use client";

import type React from "react";

import { useState } from "react";
import { Eye, EyeOff, Github, Mail } from "lucide-react";
import { Button } from "@/components/react/ui/button";
import { Input } from "@/components/react/ui/input";
import { Label } from "@/components/react/ui/label";
import { Separator } from "@/components/react/ui/separator";
import { Checkbox } from "@/components/react/ui/checkbox";
import { Link } from "./link";

export function LoginForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [showPassword, setShowPassword] = useState(false);

	async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsLoading(true);

		// Simulate authentication
		setTimeout(() => {
			setIsLoading(false);
		}, 1500);
	}

	return (
		<div className="space-y-6">
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
				<div className="space-y-2">
					<div className="flex items-center justify-between">
						<Label htmlFor="password">Password</Label>
						<Link
							href="/auth/reset-password"
							className="text-sm text-primary hover:underline"
						>
							Forgot password?
						</Link>
					</div>
					<div className="relative">
						<Input
							id="password"
							type={showPassword ? "text" : "password"}
							placeholder="••••••••"
							required
							disabled={isLoading}
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
				</div>
				<div className="flex items-center space-x-2">
					<Checkbox id="remember" />
					<Label htmlFor="remember" className="text-sm font-normal">
						Remember me
					</Label>
				</div>
				<Button type="submit" className="w-full" disabled={isLoading}>
					{isLoading ? "Signing in..." : "Sign in"}
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
				Don&apos;t have an account?{" "}
				<Link href="/auth/signup" className="text-primary hover:underline">
					Sign up
				</Link>
			</div>
		</div>
	);
}
