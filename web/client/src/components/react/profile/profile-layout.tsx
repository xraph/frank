import {ProfileSidebar} from "./profile-sidebar.tsx"
import {SidebarInset, SidebarProvider,} from "@/components/react/ui/sidebar"
import {ProfileHeader} from "@/components/react/profile/profile-header.tsx";
import React from "react";
import {authMeOptions} from "frank-sdk/react";
import type {User} from "frank-sdk";
import {useQuery} from "@tanstack/react-query";


export default function ProfileLayout({ children}: { children: ((user: User) => React.ReactNode) | React.ReactNode }) {
    const {data, isLoading} = useQuery({
        ...authMeOptions({}),
    })

    if (isLoading) {
        return <div>Loading...</div>
    }


    if (!data) {
        return <div>Error getting user hmm...</div>
    }


    return (
        <SidebarProvider>
            <ProfileSidebar user={data} />
            <SidebarInset>
                <ProfileHeader />
                <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
                    {typeof children === 'function' ? children(data) : children}
                </div>
            </SidebarInset>
        </SidebarProvider>
    )
}
