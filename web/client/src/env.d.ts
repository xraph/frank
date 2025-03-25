import type {User} from 'frank-sdk'

declare namespace App {
    interface Locals {
        user?: User
        isLoggedIn: boolean
    }
}