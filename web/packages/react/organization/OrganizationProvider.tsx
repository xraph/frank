import React, {useEffect, useState} from 'react';
import {
    OrganizationResponse,
    organizationsAddMember,
    organizationsGet,
    organizationsList,
    organizationsRemoveMember
} from '../../sdk/index';
import {OrganizationContext} from './OrganizationContext';
import {OrganizationProviderProps} from './types';
import {getAuthClient} from '../utils/api';
import {setConfig} from '../config';

export const OrganizationProvider: React.FC<OrganizationProviderProps> = ({
                                                                              children,
                                                                              organizationId
                                                                          }) => {
    const [currentOrganization, setCurrentOrganization] = useState<OrganizationResponse | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [error, setError] = useState<Error | null>(null);

    // Initialize with the provided organizationId
    useEffect(() => {
        if (organizationId) {
            setConfig({ organizationId });
            getOrganization(organizationId)
                .then(organization => {
                    if (organization) {
                        setCurrentOrganization(organization);
                    }
                })
                .catch(err => {
                    setError(err instanceof Error ? err : new Error('Failed to fetch organization'));
                });
        }
    }, [organizationId]);

    const switchOrganization = async (orgId: string): Promise<OrganizationResponse | null> => {
        setIsLoading(true);
        setError(null);

        try {
            const organization = await getOrganization(orgId);
            if (organization) {
                setCurrentOrganization(organization);
                setConfig({ organizationId: orgId });
            }
            return organization;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to switch organization'));
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    const getOrganization = async (orgId: string): Promise<OrganizationResponse | null> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            const { data } = await organizationsGet({
                client,
                path: {
                    id: orgId
                },
                throwOnError: true,
            });

            return data;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to get organization'));
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    const listOrganizations = async (): Promise<OrganizationResponse[]> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            const { data } = await organizationsList({ client, throwOnError: true });

            return data.data;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to list organizations'));
            return [];
        } finally {
            setIsLoading(false);
        }
    };

    const addMember = async (data: any): Promise<boolean> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            await organizationsAddMember({
                client,
                ...data
            });

            return true;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to add member'));
            return false;
        } finally {
            setIsLoading(false);
        }
    };

    const removeMember = async (data: any): Promise<boolean> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            await organizationsRemoveMember({
                client,
                ...data
            });

            return true;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to remove member'));
            return false;
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <OrganizationContext.Provider
            value={{
                currentOrganization,
                isLoading,
                error,
                switchOrganization,
                getOrganization,
                listOrganizations,
                addMember,
                removeMember
            }}
        >
            {children}
        </OrganizationContext.Provider>
    );
};