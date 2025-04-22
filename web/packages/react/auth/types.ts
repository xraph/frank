import {
	InternalServerError,
	LoginRequest,
	LoginResponse2,
	RegisterRequest,
	User,
} from "../../sdk";
import { AuthState, TokenData } from "../types";

export interface AuthContextType extends AuthState {
	login: (
		credentials: LoginRequest,
		afterLogin?: (rsp: LoginResponse2) => void | Promise<void>,
		onError?: (e: InternalServerError) => void,
	) => Promise<User | null>;
	logout: () => Promise<void>;
	register: (data: RegisterRequest) => Promise<User | null>;
	refreshToken: () => Promise<TokenData | null>;
	updateUser: (user: Partial<User>) => Promise<User | null>;
}

export interface AuthProviderProps {
	children: React.ReactNode;
	organizationId?: string;
}
