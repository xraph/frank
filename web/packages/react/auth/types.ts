import { LoginRequest, RegisterRequest, User } from "../../sdk";
import { AuthState, TokenData } from "../types";

export interface AuthContextType extends AuthState {
	login: (credentials: LoginRequest) => Promise<User | null>;
	logout: () => Promise<void>;
	register: (data: RegisterRequest) => Promise<User | null>;
	refreshToken: () => Promise<TokenData | null>;
	updateUser: (user: Partial<User>) => Promise<User | null>;
}

export interface AuthProviderProps {
	children: React.ReactNode;
	organizationId?: string;
}
