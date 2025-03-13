import { defineAction } from 'astro:actions';
import { z } from 'astro:schema';
import {FrankAPI} from "@/client";

export const server = {
    login: defineAction({
        input: z.object({
            email: z.string(),
            password: z.string(),
        }),
        output: z.object({
            token: z.string(),
        }),
        handler: async () => {
            const api = new FrankAPI({})
        }
    })
}