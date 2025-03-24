"use client"

import {type LucideIcon,} from "lucide-react"
import {SidebarGroup, SidebarMenu, SidebarMenuButton, SidebarMenuItem,} from "@/components/react/ui/sidebar"

export function NavProfile({
                                paths,
                            }: {
    paths: {
        title: string
        href: string
        icon: LucideIcon
    }[]
}) {
    return (
        <SidebarGroup className="group-data-[collapsible=icon]:hidden">
            {/*<SidebarGroupLabel>Projects</SidebarGroupLabel>*/}
            <SidebarMenu>
                {paths.map((item) => (
                    <SidebarMenuItem key={item.title}>
                        <SidebarMenuButton asChild>
                            <a href={item.href}>
                                <item.icon />
                                <span>{item.title}</span>
                            </a>
                        </SidebarMenuButton>
                    </SidebarMenuItem>
                ))}
            </SidebarMenu>
        </SidebarGroup>
    )
}
