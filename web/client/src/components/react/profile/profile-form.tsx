"use client"

import type React from "react"
import {useState} from "react"
import {useAuthMe, useUsersUpdateMe} from "frank-sdk/react"
import {Button} from "@/components/react/ui/button"
import {Input} from "@/components/react/ui/input"
import {Label} from "@/components/react/ui/label"
import {Textarea} from "@/components/react/ui/textarea"
import {Avatar, AvatarFallback, AvatarImage} from "@/components/react/ui/avatar"
import {Card, CardContent} from "@/components/react/ui/card"
import {AlertCircle, CheckCircle2, Upload} from "lucide-react"
import {Alert, AlertDescription, AlertTitle} from "@/components/react/ui/alert"
import {Switch} from "@/components/react/ui/switch"
import {Separator} from "@/components/react/ui/separator"

export function ProfileForm() {
    const [isLoading, setIsLoading] = useState(false)
    const [success, setSuccess] = useState("")
    const [error, setError] = useState("")

    const {data, isLoading: userIsLoading} = useAuthMe()
    const updateMe = useUsersUpdateMe()

    async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
        event.preventDefault()

        const formData = new FormData(event.currentTarget)
        const payload = {
            first_name: formData.get("first-name") as string,
            last_name: formData.get("last-name") as string,
            // bio: formData.get("bio"),
            // public_email: formData.get("email"),
            // public_projects: formData.get("public-projects") === "on",
            // public_activity: formData.get("public-activity") === "on",
        }
        setIsLoading(true)

        console.log(payload)
        setError("")
        setSuccess("")

        try {
            const o = await updateMe.mutateAsync({
                data: {
                    ...payload,
                }
            })
            if (o.status === 200) {
                setSuccess("Your profile has been updated successfully.")
            } else {
                setError(o.data?.message)
            }
        } catch (e) {
            setError(e?.message)
        }
        setIsLoading(false)
    }


    if (userIsLoading || !data?.data) {
        return <div>Loading...</div>
    }

    return (
        <div className="space-y-8">
            {error && (
                <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            {success && (
                <Alert variant="default" className="border-green-500 bg-green-500/10 text-green-500">
                    <CheckCircle2 className="h-4 w-4" />
                    <AlertTitle>Success</AlertTitle>
                    <AlertDescription>{success}</AlertDescription>
                </Alert>
            )}

            <form onSubmit={onSubmit} className="space-y-8">
                <Card>
                    <CardContent className="p-6">
                        <div className="flex flex-col gap-8 md:flex-row">
                            <div className="flex flex-col items-center gap-2">
                                <Avatar className="h-28 w-28">
                                    <AvatarImage src="/placeholder.svg?height=112&width=112" alt="Avatar" />
                                    <AvatarFallback className="text-2xl">JD</AvatarFallback>
                                </Avatar>
                                <Button type="button" variant="outline" size="sm" className="mt-2">
                                    <Upload className="mr-2 h-4 w-4" />
                                    Change avatar
                                </Button>
                            </div>

                            <div className="flex-1 space-y-4">
                                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label htmlFor="first-name">First name</Label>
                                        <Input id="first-name" name="first-name" defaultValue={data?.data?.first_name} disabled={isLoading} />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="last-name">Last name</Label>
                                        <Input id="last-name" name="last-name" defaultValue={data?.data?.last_name} disabled={isLoading} />
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="email">Email</Label>
                                    <Input id="email" name="email" type="email" defaultValue={data?.data?.email} disabled />
                                    <p className="text-xs text-muted-foreground">
                                        Your email cannot be changed. Contact support for help.
                                    </p>
                                </div>

                                {/*<div className="space-y-2">*/}
                                {/*    <Label htmlFor="username">Username</Label>*/}
                                {/*    <Input id="username" defaultValue="johndoe" disabled={isLoading} />*/}
                                {/*</div>*/}
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardContent className="p-6 space-y-4">
                        <div>
                            <h4 className="text-sm font-medium">About</h4>
                            <p className="text-sm text-muted-foreground">Tell others a little about yourself.</p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="bio">Bio</Label>
                            <Textarea
                                id="bio"
                                placeholder="Write a short bio..."
                                className="min-h-[120px]"
                                defaultValue="Software developer with a passion for building beautiful user interfaces."
                                disabled={isLoading}
                            />
                            <p className="text-xs text-muted-foreground">Your bio will be shown on your public profile.</p>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardContent className="p-6 space-y-4">
                        <div>
                            <h4 className="text-sm font-medium">Public profile</h4>
                            <p className="text-sm text-muted-foreground">Control what information is visible to others.</p>
                        </div>

                        <Separator />

                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label htmlFor="public-email">Show email on profile</Label>
                                    <p className="text-xs text-muted-foreground">Your email will be visible to other users.</p>
                                </div>
                                <Switch id="public-email" defaultChecked={false} />
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label htmlFor="public-projects">Show projects on profile</Label>
                                    <p className="text-xs text-muted-foreground">Your projects will be visible to other users.</p>
                                </div>
                                <Switch id="public-projects" defaultChecked={true} />
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label htmlFor="public-activity">Show activity on profile</Label>
                                    <p className="text-xs text-muted-foreground">Your activity will be visible to other users.</p>
                                </div>
                                <Switch id="public-activity" defaultChecked={true} />
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <div className="flex justify-end">
                    <Button type="submit" disabled={isLoading}>
                        {isLoading ? "Saving..." : "Save changes"}
                    </Button>
                </div>
            </form>
        </div>
    )
}

