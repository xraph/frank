"use client";

import type React from "react";
import { FrankUIKit } from "@frank-auth/react";

export function RegisterForm() {
	return (
		<FrankUIKit
			initialView="signup"
			title="Create an account"
			description="Enter your information to get started"
			showTabs={false}
		/>
	);
}
