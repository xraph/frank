import {defineMiddleware, sequence} from "astro:middleware";
import {authMe} from "frank-sdk";

const publicRoutes = [
    "/login",
    "/signup",
    "/register",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
];

// `context` and `next` are automatically typed
const auth = defineMiddleware(async (context, next) => {
    try {
        context.locals.isLoggedIn = false
        const user = await authMe()
        if (user.response.ok) {
            context.locals.user = user.data
            context.locals.isLoggedIn = true
        }
    } catch (err) {
        // console.log(err)
    }

    // return a Response or the result of calling `next()`
    return next();
});

const protectRoute = defineMiddleware(async (context, next) => {
    // if (!context.locals.isLoggedIn && !publicRoutes.includes(context.url.pathname)) {
    //     // If the user is not logged in, update the Request to render the `/login` route and
    //     // add header to indicate where the user should be sent after a successful login.
    //     // Return a new `context` to any following middlewares.
    //     return next(new Request(`${context.url.origin}/login?redirect=${context.url.pathname}`, {
    //         headers: {
    //             "x-redirect-to": context.url.pathname
    //         },
    //     }));
    // }

    return next();
});

export const onRequest = sequence(auth, protectRoute);