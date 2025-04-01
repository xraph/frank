'use client'

import {ProfileSidebar} from "./profile-sidebar";
import {SidebarInset, SidebarProvider} from "@/components/ui/sidebar";
import {ProfileHeader} from "@/components/account/profile-header";
import React from "react";
import {authMeOptions} from "@frank-auth/sdk/query";
import type {User} from "@frank-auth/sdk";
import {useQuery} from "@tanstack/react-query";

export default function ProfileLayout({
	children,
}: { children: ((user: User) => React.ReactNode) | React.ReactNode }) {
	const { data, isLoading } = useQuery({
		...authMeOptions({}),
	});

	if (isLoading) {
		return <div>Loading...</div>;
	}

	if (!data) {
		return <div>Error getting user hmm...</div>;
	}

	return (
		<SidebarProvider>
			<ProfileSidebar user={data} />
			<SidebarInset>
				<ProfileHeader />
				<div className="flex flex-1 flex-col gap-4 p-4 pt-0">
					{typeof children === "function" ? children(data) : children}
				</div>
			</SidebarInset>
		</SidebarProvider>
	);
}
