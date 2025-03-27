// Create a hook to use the Frank context
import { useContext } from "react";
import { FrankContext } from "@/components/context";

export function useFrank() {
	const context = useContext(FrankContext);
	if (context === undefined) {
		throw new Error("useAuthKit must be used within an FrankProvider");
	}
	return context;
}

// Create specialized hooks for common use cases
export function useSession() {
	const { session, isLoading } = useFrank();
	return { session, isLoading };
}

export function useCurrentUser() {
	const { user, isLoading } = useFrank();
	return { user, isLoading };
}

export function useAuthenticated() {
	const { isAuthenticated, isLoading } = useFrank();
	return { isAuthenticated, isLoading };
}
