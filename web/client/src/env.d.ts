import type {User} from 'sdk'

declare namespace App {
    interface Locals {
        user?: User
        isLoggedIn: boolean
    }
}