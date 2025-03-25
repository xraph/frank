"use client"

import * as React from "react"
import type {User} from "sdk"
import {Bell, Lock, Mail, Shield, UserIcon,} from "lucide-react"
import {NavProfile} from "./nav-profile"
// import {TeamSwitcher} from "@/components/react/team-switcher"
import {
    Sidebar,
    SidebarContent,
    SidebarFooter,
    SidebarHeader,
    SidebarRail,
    useSidebar,
} from "@/components/react/ui/sidebar"
import {NavUser} from "./nav-user"
import {Logo} from "@/components/react/logo.tsx";

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
            href: "/profile",
            icon: UserIcon,
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
            title: "Notifications",
            href: "/profile/notifications",
            icon: Bell,
        },
        {
            title: "Email",
            href: "/profile/email",
            icon: Mail,
        },
    ],
}

export function ProfileSidebar({ ...props }: React.ComponentProps<typeof Sidebar> & {user: User}) {
    const { toggleSidebar } = useSidebar()

    return (
        <Sidebar collapsible="icon" {...props}>
            <SidebarHeader>
                <div className="flex h-8 items-center space-x-3">
                    <Logo className="h-8 w-8" />
                    <p className="text-md font-bold text-muted-foreground">
                        Frank Auth
                    </p>
                </div>
            </SidebarHeader>
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
