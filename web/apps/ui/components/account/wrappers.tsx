import { DataProviders } from "@/components/data-providers";
import ProfileLayout from "./profile-layout";
import React from "react";
import { type User } from "@frank-auth/sdk";
import { SecurityForm } from "@/components/account/security-form";
import { PasswordForm } from "@/components/account/password-form";
import { ProfileForm } from "@/components/account/profile-form";

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
