import * as pkg from "frank-sdk/react";
import {queryClient} from './client';
import React from "react";

const {QueryClientProvider} = pkg;

export function DataProviders({children}: { children: React.ReactNode}) {
    return (
        <QueryClientProvider client={queryClient}>
            {children}
        </QueryClientProvider>
    );
}
