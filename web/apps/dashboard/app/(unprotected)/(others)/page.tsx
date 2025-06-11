import { Button } from "@/components/ui/button";

export default function Home() {
	return (
		<div className="max-w-3xl mx-auto text-center space-y-8">
			<h1 className="text-5xl font-bold tracking-tight">
				Frank a Beautiful Authentication
			</h1>
			<p className="text-xl text-muted-foreground max-w-2xl mx-auto">
				A complete authentication solution with login, registration, password
				reset, email verification, and more.
			</p>
			<div className="flex items-center justify-center gap-4">
				<Button size="lg">
					<a href="/signup">Get started</a>
				</Button>
				<Button variant="outline" size="lg">
					<a href="/login">View demo</a>
				</Button>
			</div>
		</div>
	);
}
