/// <reference types="node" />
import * as xml2js from "xml2js";
import * as crypto from "crypto";
import * as querystring from "querystring";
import { CacheProvider as InMemoryCacheProvider } from "./inmemory-cache-provider";
import type { Request } from "express";
import { ParsedQs } from "qs";
import { AudienceRestrictionXML, AuthenticateOptions, AuthorizeOptions, Profile, RequestWithUser, SamlOptions, XMLOutput } from "./types";
interface NameID {
    value: string | null;
    format: string | null;
}
declare class SAML {
    options: SamlOptions;
    cacheProvider: InMemoryCacheProvider;
    constructor(options: Partial<SamlOptions>);
    initialize(options: Partial<SamlOptions>): SamlOptions;
    getProtocol(req: Request | {
        headers?: undefined;
        protocol?: undefined;
    }): string;
    getCallbackUrl(req: Request | {
        headers?: undefined;
        protocol?: undefined;
    }): string;
    generateUniqueID(): string;
    generateInstant(): string;
    signRequest(samlMessage: querystring.ParsedUrlQueryInput): void;
    generateAuthorizeRequestAsync(req: Request, isPassive: boolean, isHttpPostBinding: boolean): Promise<string | undefined>;
    generateLogoutRequest(req: RequestWithUser): Promise<string>;
    generateLogoutResponse(req: Request, logoutRequest: Profile): string;
    requestToUrlAsync(request: string | null | undefined, response: string | null, operation: string, additionalParameters: querystring.ParsedUrlQuery): Promise<string>;
    getAdditionalParams(req: Request, operation: string, overrideParams?: querystring.ParsedUrlQuery): querystring.ParsedUrlQuery;
    getAuthorizeUrlAsync(req: Request, options: AuthorizeOptions): Promise<string>;
    getAuthorizeFormAsync(req: Request): Promise<string>;
    getLogoutUrlAsync(req: RequestWithUser, options: AuthenticateOptions & AuthorizeOptions): Promise<string>;
    getLogoutResponseUrl(req: RequestWithUser, options: AuthenticateOptions & AuthorizeOptions, callback: (err: Error | null, url?: string | null) => void): void;
    getLogoutResponseUrlAsync(req: RequestWithUser, options: AuthenticateOptions & AuthorizeOptions): Promise<string>;
    certToPEM(cert: string): string;
    certsToCheck(): Promise<undefined | string[]>;
    validateSignature(fullXml: string, currentNode: HTMLElement, certs: string[]): boolean;
    validateSignatureForCert(signature: string | Node, cert: string, fullXml: string, currentNode: HTMLElement): boolean;
    validatePostResponseAsync(container: Record<string, string>): Promise<{
        profile?: Profile | null;
        loggedOut?: boolean;
    }>;
    validateInResponseTo(inResponseTo: string | null): Promise<void>;
    validateRedirectAsync(container: ParsedQs, originalQuery: string | null): Promise<{
        profile?: Profile | null;
        loggedOut?: boolean;
    }>;
    hasValidSignatureForRedirect(container: ParsedQs, originalQuery: string | null): Promise<boolean | void>;
    validateSignatureForRedirect(urlString: crypto.BinaryLike, signature: string, alg: string, cert: string): boolean;
    verifyLogoutRequest(doc: XMLOutput): void;
    verifyLogoutResponse(doc: XMLOutput): Promise<true | void>;
    verifyIssuer(samlMessage: XMLOutput): void;
    processValidlySignedAssertionAsync(xml: xml2js.convertableToString, samlResponseXml: string, inResponseTo: string): Promise<{
        profile: Profile;
        loggedOut: boolean;
    }>;
    checkTimestampsValidityError(nowMs: number, notBefore: string, notOnOrAfter: string): Error | null;
    checkAudienceValidityError(expectedAudience: string, audienceRestrictions: AudienceRestrictionXML[]): Error | null;
    validatePostRequestAsync(container: Record<string, string>): Promise<{
        profile?: Profile;
        loggedOut?: boolean;
    }>;
    getNameIDAsync(self: SAML, doc: Node): Promise<NameID>;
    generateServiceProviderMetadata(decryptionCert: string | null, signingCert?: string | null): string;
    keyToPEM(key: crypto.KeyLike): crypto.KeyLike;
    normalizeNewlines(xml: string): string;
}
export { SAML };
