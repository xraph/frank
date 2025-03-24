import { useRef } from "react";
import { frankApi } from "@/client/api.ts";

export function useFrank() {
	const api = useRef(frankApi);
	return api.current;
}
