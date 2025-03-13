import {AuthApi, Configuration, MFAApi, OrganizationsApi, HealthApi, ReadinessApi, type FetchAPI} from '@/sdk'
import isomorphicFetch from "isomorphic-fetch";

const BASE_PATH = "/"

export class FrankAPI {
    readonly auth: AuthApi
    readonly config: Configuration
    readonly organisation: OrganizationsApi
    readonly mfa: MFAApi
    readonly health: HealthApi
    readonly readiness: ReadinessApi

    constructor(
        config: Configuration,
        protected basePath: string = BASE_PATH,
        protected fetch: FetchAPI = isomorphicFetch,
        ) {
        this.config = config
        this.auth = new AuthApi(config, basePath, fetch)
        this.organisation = new OrganizationsApi(config, basePath, fetch)
        this.mfa = new MFAApi(config, basePath, fetch)
        this.health = new HealthApi(config, basePath, fetch)
        this.readiness = new ReadinessApi(config, basePath, fetch)
    }
}