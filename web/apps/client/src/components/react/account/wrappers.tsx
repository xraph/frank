import { DataProviders } from "@/components/react/data-providers.tsx";
import ProfileLayout from "./profile-layout";
import React from "react";
import { type User } from "@frank-auth/sdk";
import { SecurityForm } from "@/components/react/account/security-form.tsx";
import { PasswordForm } from "@/components/react/account/password-form.tsx";
import { ProfileForm } from "@/components/react/account/profile-form.tsx";

export function AccountRootLayout({
	children,
}: { children: ((user: User) => React.ReactNode) | React.ReactNode }) {
	return (
		<DataProviders>
			<ProfileLayout>{children}</ProfileLayout>
		</DataProviders>
	);
}

export function AccountPasswordLayout({
	children,
}: { children?: React.ReactNode; user?: User }) {
	return (
		<DataProviders>
			{children}
			<PasswordForm />
		</DataProviders>
	);
}

export function AccountSecurityLayout({
	children,
}: { children?: React.ReactNode; user?: User }) {
	return (
		<DataProviders>
			{children}
			<SecurityForm />
		</DataProviders>
	);
}

export function AccountIndexLayout({
	children,
}: { children?: React.ReactNode; user?: User }) {
	return (
		<DataProviders>
			{children}
			<ProfileForm />
		</DataProviders>
	);
}
