import {
	OrganizationResponse,
	OrganizationsAddMemberData,
	OrganizationsRemoveMemberData,
} from "@frank-auth/sdk";

export interface OrganizationContextType {
	currentOrganization: OrganizationResponse | null;
	isLoading: boolean;
	error: Error | null;
	switchOrganization: (
		organizationId: string,
	) => Promise<OrganizationResponse | null>;
	getOrganization: (
		organizationId: string,
	) => Promise<OrganizationResponse | null>;
	listOrganizations: () => Promise<OrganizationResponse[]>;
	addMember: (data: OrganizationsAddMemberData) => Promise<boolean>;
	removeMember: (data: OrganizationsRemoveMemberData) => Promise<boolean>;
}

export interface OrganizationProviderProps {
	children: React.ReactNode;
	organizationId?: string;
}
