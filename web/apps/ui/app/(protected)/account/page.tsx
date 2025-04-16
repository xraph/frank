import React from "react";
import { ProfileForm } from "@/components/account/profile-form";

export default function Home() {
	return (
		<div className="space-y-6">
			<div>
				<h3 className="text-lg font-medium">Profile</h3>
				<p className="text-sm text-muted-foreground">
					This is how others will see you on the platform.
				</p>
			</div>
			<ProfileForm />
		</div>
	);
}
