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
			entry: path.resolve(__dirname, "index.ts"),
			name: "FrankAuth",
			formats: ["es", "cjs"],
			fileName: (format) => `index.${format === "es" ? "mjs" : "cjs"}`,
		},
		rollupOptions: {
			external: ["react", "react-dom"],
			output: {
				globals: {
					react: "React",
					"react-dom": "ReactDOM",
				},
			},
		},
	},
});
