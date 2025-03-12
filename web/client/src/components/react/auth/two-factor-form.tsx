"use client"

import type React from "react"

import { useState } from "react"
import { Link } from './link'
import { Button } from "@/components/react/ui/button"
import { Input } from "@/components/react/ui/input"
import { Label } from "@/components/react/ui/label"
import { AlertCircle, ArrowLeft } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/react/ui/alert"

export function TwoFactorForm() {
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState("")
    const [code, setCode] = useState(["", "", "", "", "", ""])

    function handleCodeChange(index: number, value: string) {
        if (value.length > 1) {
            value = value.charAt(0)
        }

        const newCode = [...code]
        newCode[index] = value
        setCode(newCode)

        // Auto-focus next input
        if (value && index < 5) {
            const nextInput = document.getElementById(`2fa-${index + 1}`)
            if (nextInput) {
                nextInput.focus()
            }
        }
    }

    async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
        event.preventDefault()
        setIsLoading(true)
        setError("")

        // Simulate 2FA verification
        setTimeout(() => {
            setIsLoading(false)
            // Redirect would happen here in a real app
        }, 1500)
    }

    return (
        <div className="space-y-6">
            {error && (
                <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            <form onSubmit={onSubmit} className="space-y-4">
                <div className="space-y-2">
                    <Label htmlFor="2fa-0">Authentication code</Label>
                    <div className="flex gap-2">
                        {code.map((digit, index) => (
                            <Input
                                key={index}
                                id={`2fa-${index}`}
                                type="text"
                                inputMode="numeric"
                                pattern="[0-9]*"
                                maxLength={1}
                                className="h-12 w-12 text-center text-lg"
                                value={digit}
                                onChange={(e) => handleCodeChange(index, e.target.value)}
                                required
                                disabled={isLoading}
                            />
                        ))}
                    </div>
                </div>
                <Button type="submit" className="w-full" disabled={isLoading || code.some((d) => !d)}>
                    {isLoading ? "Verifying..." : "Verify"}
                </Button>
            </form>

            <div className="text-center text-sm">
                <Link href="/auth/login" className="text-primary hover:underline">
                    <ArrowLeft className="mr-2 h-4 w-4 inline" />
                    Back to login
                </Link>
            </div>
        </div>
    )
}

