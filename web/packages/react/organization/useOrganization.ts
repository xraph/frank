'use client'

import {useOrganizationContext} from "./OrganizationContext";

export const useOrganization = () => {
	return useOrganizationContext();
};
