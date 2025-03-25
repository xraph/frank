import {DataProviders} from "@/components/react/data-providers.tsx";
import React from "react";
import {SecurityForm} from "@/components/react/profile/security-form.tsx";
import {type User} from "sdk";

export function ProfileSecurityLayout({children}: { children?: React.ReactNode, user?: User}) {
    return (
        <DataProviders>
            {children}
            <SecurityForm />
        </DataProviders>
    );
}
