'use client'

import {useState} from "react";
import {InternalServerError, LoginRequest, LoginResponse2, User,} from "@frank-auth/sdk";
import {useAuth} from "./useAuth";

export const useLogin = () => {
	const { login } = useAuth();
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<Error | null>(null);

	const handleLogin = async (
		credentials: LoginRequest,
		afterLogin?: (rsp: LoginResponse2) => void | Promise<void>,
		onError?: (e: InternalServerError) => void,
	): Promise<User | null> => {
		setIsLoading(true);
		setError(null);

		try {
			const user = await login(credentials, afterLogin, onError);
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
