import {Avatar, AvatarFallback, AvatarImage,} from "@/components/ui/avatar";

export function UserAvatar() {
	return (
		<Avatar className="h-28 w-28">
			<AvatarImage src="/placeholder.svg?height=112&width=112" alt="Avatar" />
			<AvatarFallback className="text-2xl">JD</AvatarFallback>
		</Avatar>
	);
}
