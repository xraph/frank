import {DataProviders} from "@/components/react/data-providers.tsx";
import ProfileLayout from "./profile-layout";
import React from "react";
import {type User} from "sdk";

export function ProfileRootLayout({children}: { children: ((user: User) => React.ReactNode) | React.ReactNode}) {
    return (
        <DataProviders>
            <ProfileLayout>
                {children}
            </ProfileLayout>
        </DataProviders>
    );
}
