import Header from "./header";

export default function Layout({ children }: { children: React.ReactNode }) {
	return (
		<div className="min-w-full min-h-svh">
			<div className="flex flex-col min-h-dvh">
				<Header />
				<main className="flex-1 flex bg-background h-full items-center justify-center">
					<div className="container">{children}</div>
				</main>
			</div>
		</div>
	);
}
