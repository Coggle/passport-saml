import { AbstractStrategy } from "./strategy";
import type { Request } from "express";
import { AuthenticateOptions, MultiStrategyConfig, RequestWithUser, VerifyWithoutRequest, VerifyWithRequest } from "./types";
import { SamlConfig } from ".";
export declare class MultiSamlStrategy extends AbstractStrategy {
    static readonly newSamlProviderOnConstruct = false;
    _options: SamlConfig & MultiStrategyConfig;
    constructor(options: MultiStrategyConfig, verify: VerifyWithRequest);
    constructor(options: MultiStrategyConfig, verify: VerifyWithoutRequest);
    authenticate(req: RequestWithUser, options: AuthenticateOptions): void;
    logout(req: RequestWithUser, callback: (err: Error | null, url?: string | null | undefined) => void): void;
    generateServiceProviderMetadata(req: Request, decryptionCert: string | null, signingCert: string | null, callback: (err: Error | null, metadata?: string) => void): void;
    error(err: Error): void;
}
