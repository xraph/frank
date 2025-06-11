"use client";

import * as React from "react";
import type { User } from "@frank-auth/sdk";
import { Bell, Lock, Mail, Shield, UserIcon } from "lucide-react";
import { NavProfile } from "./nav-profile";
// import {TeamSwitcher} from "@/components/react/team-switcher"
import {
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarHeader,
	SidebarRail,
	useSidebar,
} from "@/components/ui/sidebar";
import { NavUser } from "./nav-user";
import { Logo } from "@/components/logo";

// This is sample data.
const data = {
	user: {
		name: "shadcn",
		email: "m@example.com",
		avatar: "/avatars/shadcn.jpg",
	},
	projects: [
		{
			title: "Account",
			href: "/account",
			icon: UserIcon,
		},
		{
			title: "Security",
			href: "/account/security",
			icon: Shield,
		},
		{
			title: "Password",
			href: "/account/password",
			icon: Lock,
		},
		{
			title: "Notifications",
			href: "/account/notifications",
			icon: Bell,
		},
		{
			title: "Email",
			href: "/account/email",
			icon: Mail,
		},
	],
};

export function ProfileSidebar({
	...props
}: React.ComponentProps<typeof Sidebar> & { user: User }) {
	const { toggleSidebar } = useSidebar();

	return (
		<Sidebar collapsible="icon" {...props}>
			<SidebarHeader>
				<div className="flex h-8 items-center space-x-3">
					<Logo className="h-8 w-8" />
					<p className="text-md font-bold text-muted-foreground">Frank Auth</p>
				</div>
			</SidebarHeader>
			<SidebarContent>
				<NavProfile paths={data.projects} />
			</SidebarContent>
			<SidebarFooter>
				<NavUser user={props.user} />
			</SidebarFooter>
			<SidebarRail onClick={() => toggleSidebar()} />
		</Sidebar>
	);
}
