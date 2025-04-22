"use client";

import React from "react";
import "@/client";
import { FrankUIKit } from "@frank-auth/react";

export function LoginForm() {
	return <FrankUIKit showTabs={false} useProviderConfig={true} />;
}
