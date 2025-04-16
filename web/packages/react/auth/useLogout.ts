import { useState } from "react";
import { useAuth } from "./useAuth";

export const useLogout = () => {
	const { logout } = useAuth();
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<Error | null>(null);

	const handleLogout = async (): Promise<boolean> => {
		setIsLoading(true);
		setError(null);

		try {
			await logout();
			return true;
		} catch (err) {
			const errorMessage =
				err instanceof Error ? err : new Error("Logout failed");
			setError(errorMessage);
			return false;
		} finally {
			setIsLoading(false);
		}
	};

	return {
		logout: handleLogout,
		isLoading,
		error,
	};
};
