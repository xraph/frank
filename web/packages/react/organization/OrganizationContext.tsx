'use client'

import React, {createContext} from "react";
import {OrganizationContextType} from "./types";

// Create organization context with default values
export const OrganizationContext = createContext<OrganizationContextType>({
	currentOrganization: null,
	isLoading: false,
	error: null,
	switchOrganization: async () => null,
	getOrganization: async () => null,
	listOrganizations: async () => [],
	addMember: async () => false,
	removeMember: async () => false,
});

export const useOrganizationContext = () => {
	const context = React.useContext(OrganizationContext);
	if (!context) {
		throw new Error(
			"useOrganizationContext must be used within an OrganizationProvider",
		);
	}
	return context;
};
