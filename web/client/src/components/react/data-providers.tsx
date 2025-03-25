import {QueryClientProvider} from '@tanstack/react-query';
import {queryClient} from './client';
import "@/client";
import React from "react";

// const {QueryClientProvider} = pkg;

export function DataProviders({children}: { children: React.ReactNode}) {
    return (
        <QueryClientProvider client={queryClient}>
            {children}
        </QueryClientProvider>
    );
}
