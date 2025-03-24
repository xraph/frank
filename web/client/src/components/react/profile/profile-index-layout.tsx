import {DataProviders} from "@/components/react/data-providers.tsx";
import React from "react";
import {ProfileForm} from "@/components/react/profile/profile-form.tsx";
import {type User} from "frank-sdk";

export function ProfileIndexLayout({children}: { children?: React.ReactNode, user?: User}) {
    return (
        <DataProviders>
            {children}
            <ProfileForm />
        </DataProviders>
    );
}
