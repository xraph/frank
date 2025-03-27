"use client";

import React, {useState} from "react";
import {useForm} from "react-hook-form";
import "@/client";
import {authLogin} from "@frank-auth/sdk";
import {FrankUIKit} from "@frank-auth/react";

export function LoginForm() {
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const form = useForm();
	const [showPassword, setShowPassword] = useState(false);

	async function onSubmit(data: {
		email: string;
		password: string;
		rememberMe: boolean;
	}) {
		try {
			const rsp = await authLogin({
				body: {
					email: data.email,
					password: data.password,
				},
			});

			if (!rsp.response.ok) {
				setError((rsp.error as any)?.message);
				return;
			}

			location.replace("/account");
		} catch (err) {
			setError(err?.toString()?.replace("Error: ", "") ?? null);
		}
		setIsLoading(false);
	}

	return <FrankUIKit showTabs={false} />;
}
