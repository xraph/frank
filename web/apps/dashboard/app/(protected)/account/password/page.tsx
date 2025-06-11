import React from "react";
import { PasswordForm } from "@/components/account/password-form";

export default function Password() {
	return (
		<div className="space-y-6">
			<div>
				<h3 className="text-lg font-medium">Password</h3>
				<p className="text-sm text-muted-foreground">
					Update your password to keep your account secure.
				</p>
			</div>
			<PasswordForm />
		</div>
	);
}
