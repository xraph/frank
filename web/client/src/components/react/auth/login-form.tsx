"use client";

import React, {useState} from "react";
import {useForm} from "react-hook-form";
import {AlertCircle, Eye, EyeOff, Github, Mail} from "lucide-react";
import {Button} from "@/components/react/ui/button";
import {Input} from "@/components/react/ui/input";
import {Label} from "@/components/react/ui/label";
import {Separator} from "@/components/react/ui/separator";
import {Form, FormControl, FormField, FormItem, FormLabel,} from "@/components/react/ui/form";
import {Checkbox} from "@/components/react/ui/checkbox";
import {Link} from "../link.tsx";
import "@/client";
import {authLogin} from "frank-sdk";
import {Alert, AlertDescription} from "@/components/react/ui/alert";

export function LoginForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const form = useForm();
	const [showPassword, setShowPassword] = useState(false);

	async function onSubmit(data: {
		email: string;
		password: string;
		rememberMe: boolean;
	}) {
		try {
			const rsp = await authLogin({
				body: {
					email: data.email,
					password: data.password,
				}
			});

			if (!rsp.response.ok) {
				setError((rsp.error as any)?.message);
				return;
			}

			location.replace('/profile');
		} catch (err) {
			setError(err?.toString()?.replace("Error: ", "") ?? null);
		}
		setIsLoading(false);
	}

	return (
		<Form {...form}>
			<div className="space-y-6">
				{error && (
					<Alert variant="destructive">
						<AlertCircle className="h-4 w-4" />
						<AlertDescription>{error}</AlertDescription>
					</Alert>
				)}
				<form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
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
										{...field}
									/>
								</FormControl>
							</FormItem>
						)}
					/>

					<div className="space-y-2">
						<div className="flex items-center justify-between">
							<Label htmlFor="password">Password</Label>
							<Link
								href="/reset-password"
								className="text-sm text-primary hover:underline"
							>
								Forgot password?
							</Link>
						</div>
						<div className="relative">
							<FormField
								control={form.control}
								name="password"
								render={({ field }) => (
									<FormItem>
										<FormControl>
											<Input
												id="password"
												type={showPassword ? "text" : "password"}
												placeholder="••••••••"
												required
												disabled={isLoading}
												{...field}
											/>
										</FormControl>
									</FormItem>
								)}
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
					<FormField
						control={form.control}
						name="rememberMe"
						render={({ field }) => (
							<FormItem className="flex items-center space-x-2">
								<FormControl>
									<Checkbox
										id="rememberMe"
										{...field}
										onChange={(e) => {
											field.onChange(e);
										}}
									/>
								</FormControl>
								<FormLabel htmlFor="rememberMe" className="text-sm font-normal">
									Remember me
								</FormLabel>
							</FormItem>
						)}
					/>
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
					<Link href="/signup" className="text-primary hover:underline">
						Sign up
					</Link>
				</div>
			</div>
		</Form>
	);
}
