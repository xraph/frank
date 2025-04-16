import { Logo } from "@/components/logo";
import { Button } from "@/components/ui/button";
import Link from "next/link";

export default function Header({ hideNav }: { hideNav?: boolean }) {
	return (
		<header className="py-4 flex sticky top-0 items-center justify-center">
			<div className="container flex items-center justify-between">
				<div className="flex items-center gap-2">
					<Link href="/" className="inline-flex items-center gap-2">
						<Logo className="h-8 w-8" />
						<span className="font-semibold text-xl">Frank</span>
					</Link>
				</div>

				{!hideNav && (
					<div className="flex items-center gap-4">
						<Button asChild={true} variant="ghost">
							<a href="/login">Sign in</a>
						</Button>
						<Button>
							<a href="/signup">Sign up</a>
						</Button>
					</div>
				)}
			</div>
		</header>
	);
}
