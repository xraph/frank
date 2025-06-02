import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
	plugins: [react(), tailwindcss()],
	resolve: {
		alias: {
			"@": path.resolve(__dirname, "./"),
		},
	},
	define: {
		// Define __dirname for Edge Runtime compatibility
		'global.__dirname': JSON.stringify(process.cwd()),
		'__dirname': JSON.stringify(process.cwd()),
	},
	build: {
		lib: {
			entry: {
				index: path.resolve(__dirname, "index.ts"),
				next: path.resolve(__dirname, "next.ts"),
			},
			name: "FrankAuth",
			formats: ["es", "cjs"],
			fileName: (format, entryName) =>
				`${entryName}.${format === "es" ? "mjs" : "cjs"}`,
		},
		rollupOptions: {
			external: [
				"react",
				"react-dom",
				"next/server",
				"next/navigation",
				/^@radix-ui\/.*$/,
				/^@hookform\/.*$/,
				/^lucide-react$/,
				"zod",
			],
			output: {
				globals: {
					react: "React",
					"react-dom": "ReactDOM",
					"next/server": "NextServer",
				},
				preserveModules: false,
			},
		},
		target: 'es2022', // Modern target for Edge Runtime
		// minify: false, // Disable minification for debugging
	},
	optimizeDeps: {
		exclude: ['@frank-auth/sdk']
	}
});