// import {defineAction} from 'astro:actions';
// import {z} from 'astro:schema';
// import {FrankAPI} from "@/client";
//
// export const loginAction = defineAction({
//     input: z.object({
//         email: z.string(),
//         password: z.string(),
//     }),
//     handler: async (input) => {
//         const api = new FrankAPI()
//         try {
//             const rsp = await api.auth.authLogin({
//                 loginRequest: {
//                     email: input.email,
//                     password: input.password,
//                 }
//             })
//             console.log(rsp)
//
//             return rsp.token
//
//         } catch (e) {
//             console.log(e)
//         }
//     }
// })
