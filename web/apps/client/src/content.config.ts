import { z, defineCollection } from "astro:content";
import { glob } from "astro/loaders";

const legal = defineCollection({
	loader: glob({ pattern: "**/*.md", base: "./src/content/legal" }),
	schema: z.object({
		title: z.string(),
		slug: z.string(),
		updatedAt: z.string(),
	}),
});

export const collections = {
	legal,
};
