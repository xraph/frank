import {useState} from "react";
import {LoginRequest, User} from "@frank-auth/sdk";
import {useAuth} from "./useAuth";

export const useLogin = () => {
	const { login } = useAuth();
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<Error | null>(null);

	const handleLogin = async (
		credentials: LoginRequest,
	): Promise<User | null> => {
		setIsLoading(true);
		setError(null);

		try {
			const user = await login(credentials);
			return user;
		} catch (err) {
			const errorMessage =
				err instanceof Error ? err : new Error("Login failed");
			setError(errorMessage);
			return null;
		} finally {
			setIsLoading(false);
		}
	};

	return {
		login: handleLogin,
		isLoading,
		error,
	};
};
