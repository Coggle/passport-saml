import type * as express from "express";
import * as passport from "passport";
import { Profile, SamlConfig } from ".";
export interface AuthenticateOptions extends passport.AuthenticateOptions {
    samlFallback?: "login-request" | "logout-request";
    additionalParams?: Record<string, any>;
}
export interface AuthorizeOptions extends AuthenticateOptions {
    samlFallback?: "login-request" | "logout-request";
}
export interface StrategyOptions {
    name?: string;
    passReqToCallback?: boolean;
}
export interface RequestWithUser extends express.Request {
    samlLogoutRequest: any;
    user?: Profile;
}
export declare type VerifiedCallback = (err: Error | null, user?: Record<string, unknown>, info?: Record<string, unknown>) => void;
export declare type VerifyWithRequest = (req: express.Request, profile: Profile | null | undefined, done: VerifiedCallback) => void;
export declare type VerifyWithoutRequest = (profile: Profile | null | undefined, done: VerifiedCallback) => void;
export declare type StrategyOptionsCallback = (err: Error | null, samlOptions?: SamlConfig) => void;
interface BaseMultiStrategyConfig {
    getSamlOptions(req: express.Request, callback: StrategyOptionsCallback): void;
}
export declare type MultiStrategyConfig = Partial<SamlConfig> & StrategyOptions & BaseMultiStrategyConfig;
export declare class ErrorWithXmlStatus extends Error {
    readonly xmlStatus: string;
    constructor(message: string, xmlStatus: string);
}
export {};
