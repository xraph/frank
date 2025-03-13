import {useRef} from "react";
import {FrankAPI} from "@/client/api.ts";

export function useFrank() {
    const api = useRef(new FrankAPI({
        accessToken: '',
        apiKey: '',
    }))
    return api.current;
}