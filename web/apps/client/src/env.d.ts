import type { User } from "@frank-auth/sdk";

declare namespace App {
	interface Locals {
		user?: User;
		isLoggedIn: boolean;
	}
}
