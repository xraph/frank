'use client'

import {useState} from "react";
import {RegisterRequest, User} from "@frank-auth/sdk";
import {useAuth} from "./useAuth";

export const useRegister = () => {
	const { register } = useAuth();
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<Error | null>(null);

	const handleRegister = async (
		data: RegisterRequest,
	): Promise<User | null> => {
		setIsLoading(true);
		setError(null);

		try {
			const user = await register(data);
			return user;
		} catch (err) {
			const errorMessage =
				err instanceof Error ? err : new Error("Registration failed");
			setError(errorMessage);
			return null;
		} finally {
			setIsLoading(false);
		}
	};

	return {
		register: handleRegister,
		isLoading,
		error,
	};
};
