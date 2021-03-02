/// <reference types="node" />
import type * as express from "express";
import * as passport from "passport";
import type { CacheProvider } from "./inmemory-cache-provider";
export declare type CertCallback = (callback: (err: Error | null, cert?: string | string[]) => void) => void;
export declare type RACComparision = "exact" | "minimum" | "maximum" | "better";
export declare type SignatureAlgorithm = "sha1" | "sha256" | "sha512";
export interface AuthenticateOptions extends passport.AuthenticateOptions {
    samlFallback?: "login-request" | "logout-request";
    additionalParams?: Record<string, any>;
}
export interface AuthorizeOptions extends AuthenticateOptions {
    samlFallback?: "login-request" | "logout-request";
}
export interface SamlSigningOptions {
    /** @deprecated use privateKey field instead */
    privateCert?: string | Buffer;
    privateKey: string | Buffer;
    signatureAlgorithm?: SignatureAlgorithm;
    xmlSignatureTransforms?: string[];
    digestAlgorithm?: string;
}
export interface SamlOptions extends SamlSigningOptions {
    callbackUrl: string;
    path: string;
    protocol: string;
    host: string;
    entryPoint: string;
    issuer: string;
    cert: string | string[] | CertCallback;
    decryptionPvk: string | Buffer;
    additionalParams: Record<string, string>;
    additionalAuthorizeParams: Record<string, string>;
    identifierFormat: string | null;
    acceptedClockSkewMs: number;
    attributeConsumingServiceIndex: string | null;
    disableRequestedAuthnContext: boolean;
    authnContext: string | string[];
    forceAuthn: boolean;
    skipRequestCompression: boolean;
    authnRequestBinding?: string;
    RACComparison: RACComparision;
    providerName: string;
    passive: boolean;
    idpIssuer: string;
    audience: string;
    scoping: SamlScopingConfig;
    validateInResponseTo: boolean;
    requestIdExpirationPeriodMs: number;
    cacheProvider: CacheProvider;
    generateUniqueID: () => string;
    logoutUrl: string;
    additionalLogoutParams: Record<string, string>;
    logoutCallbackUrl: string;
    disableRequestACSUrl: boolean;
}
export declare type SamlConfig = Partial<SamlOptions> & StrategyOptions;
interface StrategyOptions {
    name?: string;
    passReqToCallback?: boolean;
}
export interface SamlScopingConfig {
    idpList?: SamlIDPListConfig[];
    proxyCount?: number;
    requesterId?: string[] | string;
}
export declare type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];
export declare type XMLObject = {
    [key: string]: XMLValue;
};
export declare type XMLInput = XMLObject;
export interface AuthorizeRequestXML {
    "samlp:AuthnRequest": XMLInput;
}
export interface LogoutRequestXML {
    "samlp:LogoutRequest": {
        "saml:NameID": XMLInput;
        [key: string]: XMLValue;
    };
}
export interface ServiceMetadataXML {
    EntityDescriptor: {
        [key: string]: XMLValue;
        SPSSODescriptor: XMLObject;
    };
}
export interface AudienceRestrictionXML {
    Audience?: XMLObject[];
}
export declare type XMLOutput = Record<string, any>;
export interface SamlIDPListConfig {
    entries: SamlIDPEntryConfig[];
    getComplete?: string;
}
export interface SamlIDPEntryConfig {
    providerId: string;
    name?: string;
    loc?: string;
}
export interface Profile {
    issuer?: string;
    sessionIndex?: string;
    nameID?: string;
    nameIDFormat?: string;
    nameQualifier?: string;
    spNameQualifier?: string;
    ID?: string;
    mail?: string;
    email?: string;
    ["urn:oid:0.9.2342.19200300.100.1.3"]?: string;
    getAssertionXml?(): string;
    getAssertion?(): Record<string, unknown>;
    getSamlResponseXml?(): string;
    [attributeName: string]: unknown;
}
export interface RequestWithUser extends express.Request {
    samlLogoutRequest: any;
    user?: Profile;
}
export declare type VerifiedCallback = (err: Error | null, user?: Record<string, unknown>, info?: Record<string, unknown>) => void;
export declare type VerifyWithRequest = (req: express.Request, profile: Profile | null | undefined, done: VerifiedCallback) => void;
export declare type VerifyWithoutRequest = (profile: Profile | null | undefined, done: VerifiedCallback) => void;
export declare type SamlOptionsCallback = (err: Error | null, samlOptions?: SamlConfig) => void;
export interface MultiSamlConfig extends SamlConfig {
    getSamlOptions(req: express.Request, callback: SamlOptionsCallback): void;
}
export {};
