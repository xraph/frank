"use client"

import * as React from "react"
import type {User} from "frank-sdk"
import {Bell, CreditCard, Key, Lock, LogOut, Mail, Settings, Shield, UserIcon,} from "lucide-react"
import {NavProfile} from "./nav-profile"
// import {TeamSwitcher} from "@/components/react/team-switcher"
import {Sidebar, SidebarContent, SidebarFooter, SidebarRail, useSidebar,} from "@/components/react/ui/sidebar"
import {NavUser} from "./nav-user"

// This is sample data.
const data = {
    user: {
        name: "shadcn",
        email: "m@example.com",
        avatar: "/avatars/shadcn.jpg",
    },
    projects: [
        {
            title: "Profile",
            href: "/profile",
            icon: UserIcon,
        },
        {
            title: "Account",
            href: "/profile/account",
            icon: Settings,
        },
        {
            title: "Security",
            href: "/profile/security",
            icon: Shield,
        },
        {
            title: "Password",
            href: "/profile/password",
            icon: Lock,
        },
        {
            title: "API Keys",
            href: "/profile/api-keys",
            icon: Key,
        },
        {
            title: "Notifications",
            href: "/profile/notifications",
            icon: Bell,
        },
        {
            title: "Billing",
            href: "/profile/billing",
            icon: CreditCard,
        },
        {
            title: "Email",
            href: "/profile/email",
            icon: Mail,
        },
        {
            title: "Logout",
            href: "/profile/logout",
            icon: LogOut,
        },
    ],
}

export function ProfileSidebar({ ...props }: React.ComponentProps<typeof Sidebar> & {user: User}) {
    const { toggleSidebar } = useSidebar()

    return (
        <Sidebar collapsible="icon" {...props}>
            {/*<SidebarHeader>*/}
            {/*    <TeamSwitcher teams={data.teams} />*/}
            {/*</SidebarHeader>*/}
            <SidebarContent>
                <NavProfile paths={data.projects} />
            </SidebarContent>
            <SidebarFooter>
                <NavUser user={props.user} />
            </SidebarFooter>
            <SidebarRail  onClick={() => toggleSidebar()} />
        </Sidebar>
    )
}
