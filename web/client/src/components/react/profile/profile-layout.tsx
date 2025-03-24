import {ProfileSidebar} from "./profile-sidebar.tsx"
import {SidebarInset, SidebarProvider,} from "@/components/react/ui/sidebar"
import {ProfileHeader} from "@/components/react/profile/profile-header.tsx";
import React from "react";
import {useAuthMe} from "frank-sdk/react";
import type {User} from "frank-sdk";

export default function ProfileLayout({ children}: { children: ((user: User) => React.ReactNode) | React.ReactNode }) {
    const {data, isLoading} = useAuthMe()

    if (isLoading || !data?.data) {
        return <div>Loading...</div>
    }
    

    return (
        <SidebarProvider>
            <ProfileSidebar user={data.data} />
            <SidebarInset>
                <ProfileHeader />
                <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
                    {typeof children === 'function' ? children(data.data) : children}
                </div>
            </SidebarInset>
        </SidebarProvider>
    )
}
