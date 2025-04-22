import { defineConfig } from "vite";
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
				/^@radix-ui\/.*$/,
				/^@hookform\/.*$/,
				/^lucide-react$/,
				"zod",
			],
			output: {
				globals: {
					react: "React",
					"react-dom": "ReactDOM",
				},
				preserveModules: false,
			},
		},
		// sourcemap: true,
		// minify: false,
		// rollupOptions: {
		// 	external: ["react", "react-dom"],
		// 	output: {
		// 		globals: {
		// 			react: "React",
		// 			"react-dom": "ReactDOM",
		// 		},
		// 	},
		// },
	},
});
