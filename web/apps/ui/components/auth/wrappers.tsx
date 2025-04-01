'use client'

import React from "react";
import {FrankProvider} from "@frank-auth/react";
import {LoginForm} from "./login-form";
import {RegisterForm} from "./register-form";
import {Logo} from "@/components/logo";

const prefix = process.env.NEXT_PUBLIC_AUTH_PATH_PREFIX ?? "";

export function BaseAuthLayout({ children }: { children: React.ReactNode }) {
	return (
		<FrankProvider
			initialConfig={{
				titleAlign: "left",
				theme: "purple",
				logo: <Logo className="h-10 w-10" />,
				api: {
					baseUrl: process.env.PUBLIC_FRANK_ENDPOINT,
				},
				links: {
					showAuthLinks: true,
					login: {
						preText: "Already have an account?",
						text: "Log in",
						url: `${prefix}/login`,
					},
					signup: {
						preText: "Don't have an account?",
						text: "Sign up",
						url: `${prefix}/signup`,
					},
					legal: [
						{
							text: "Privacy",
							url: `${prefix}/legal/privacy`,
						},
						{
							text: "Terms",
							url: `${prefix}/legal/terms`,
						},
					],
				},
				signupFields: [
					{
						name: "firstName",
						label: "First Name",
						type: "text" as const,
						placeholder: "John",
						isFirstName: true,
						required: true,
						row: 1,
						width: "half",
					},
					{
						name: "lastName",
						label: "Last Name",
						type: "text" as const,
						placeholder: "Doe",
						isLastName: true,
						required: true,
						row: 1,
						width: "half",
					},
					{
						name: "email",
						label: "Email",
						type: "email" as const,
						isEmail: true,
						placeholder: "name@example.com",
						required: true,
						row: 2,
						width: "full",
					},
					{
						name: "password",
						row: 3,
						placeholder: "********",
						label: "Password",
						type: "password" as const,
						required: true,
						validation: { minLength: 8 },
					},
				],
			}}
		>
			{children}
		</FrankProvider>
	);
}

export function LoginLayout() {
	return (
		<BaseAuthLayout>
			<LoginForm />
		</BaseAuthLayout>
	);
}

export function SignupLayout() {
	return (
		<BaseAuthLayout>
			<RegisterForm />
		</BaseAuthLayout>
	);
}
