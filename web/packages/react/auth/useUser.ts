import { User } from "@frank-auth/sdk";
import { useAuth } from "./useAuth";

export const useUser = (): {
	user: User | null | undefined;
	isLoading: boolean;
	error: Error | null;
	updateUser: (userData: Partial<User>) => Promise<User | null>;
} => {
	const { user, isLoading, error, updateUser } = useAuth();

	return {
		user,
		isLoading,
		error,
		updateUser,
	};
};
