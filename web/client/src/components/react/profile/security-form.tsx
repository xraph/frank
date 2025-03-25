"use client"

import type React from "react"
import {useState} from "react"
import {Button} from "@/components/react/ui/button"
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from "@/components/react/ui/card"
import {AlertCircle, CheckCircle2, Laptop, Smartphone, Trash2} from "lucide-react"
import {Alert, AlertDescription, AlertTitle} from "@/components/react/ui/alert"
import {Switch} from "@/components/react/ui/switch"
import {Separator} from "@/components/react/ui/separator"
import {Badge} from "@/components/react/ui/badge"

export function SecurityForm() {
    const [isLoading, setIsLoading] = useState(false)
    const [success, setSuccess] = useState("")
    const [error, setError] = useState("")

    const devices = [
        {
            id: 1,
            name: "MacBook Pro",
            icon: Laptop,
            location: "San Francisco, CA",
            lastActive: "Active now",
            current: true,
        },
        {
            id: 2,
            name: "iPhone 13",
            icon: Smartphone,
            location: "San Francisco, CA",
            lastActive: "3 hours ago",
            current: false,
        },
        {
            id: 3,
            name: "Windows PC",
            icon: Laptop,
            location: "New York, NY",
            lastActive: "2 days ago",
            current: false,
        },
    ]

    async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
        event.preventDefault()
        setIsLoading(true)
        setError("")
        setSuccess("")

        // Simulate security update
        setTimeout(() => {
            setIsLoading(false)
            setSuccess("Your security settings have been updated successfully.")
        }, 1500)
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
                    <CardHeader>
                        <CardTitle>Two-Factor Authentication</CardTitle>
                        <CardDescription>Add an extra layer of security to your account</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                            <div className="space-y-0.5">
                                <div className="font-medium">Authenticator App</div>
                                <div className="text-sm text-muted-foreground">
                                    Use an authenticator app to get two-factor authentication codes
                                </div>
                            </div>
                            <Switch defaultChecked={true} />
                        </div>

                        <Separator />

                        <div className="flex items-center justify-between">
                            <div className="space-y-0.5">
                                <div className="font-medium">SMS Authentication</div>
                                <div className="text-sm text-muted-foreground">Receive a code via SMS to verify your identity</div>
                            </div>
                            <Switch defaultChecked={false} />
                        </div>

                        <Separator />

                        <div className="flex items-center justify-between">
                            <div className="space-y-0.5">
                                <div className="font-medium">Email Authentication</div>
                                <div className="text-sm text-muted-foreground">Receive a code via email to verify your identity</div>
                            </div>
                            <Switch defaultChecked={false} />
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Active Sessions</CardTitle>
                        <CardDescription>Manage your active sessions across different devices</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        {devices.map((device) => (
                            <div key={device.id} className="flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className="bg-muted flex h-10 w-10 items-center justify-center rounded-full">
                                        <device.icon className="h-5 w-5" />
                                    </div>
                                    <div>
                                        <div className="font-medium flex items-center gap-2">
                                            {device.name}
                                            {device.current && (
                                                <Badge variant="outline" className="text-xs bg-primary/10">
                                                    Current
                                                </Badge>
                                            )}
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            {device.location} • {device.lastActive}
                                        </div>
                                    </div>
                                </div>
                                {!device.current && (
                                    <Button variant="ghost" size="icon">
                                        <Trash2 className="h-4 w-4" />
                                        <span className="sr-only">Remove device</span>
                                    </Button>
                                )}
                            </div>
                        ))}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Login History</CardTitle>
                        <CardDescription>Recent login activity on your account</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                            {[...Array(3)].map((_, i) => (
                                <div key={i} className="flex justify-between items-start">
                                    <div>
                                        <div className="font-medium">
                                            {i === 0 ? "Current session" : `Login ${i === 1 ? "yesterday" : "3 days ago"}`}
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            {i === 0 ? "San Francisco, CA" : i === 1 ? "San Francisco, CA" : "New York, NY"} • IP:{" "}
                                            {i === 0 ? "192.168.1.1" : i === 1 ? "192.168.1.2" : "192.168.1.3"}
                                        </div>
                                    </div>
                                    <div className="text-sm text-muted-foreground">
                                        {i === 0 ? "Now" : i === 1 ? "Yesterday, 2:30 PM" : "May 15, 2023, 10:45 AM"}
                                    </div>
                                </div>
                            ))}
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

