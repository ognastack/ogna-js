/**
 * TYPES & INTERFACES
 */
export interface Bucket {
  owner?: string;
  id?: string;
  name: string;
  public?: boolean;
}

export interface FileObj {
  last_modified: string;
  bucket_id: string;
  id: string;
  name: string;
}

export interface SimpleResponse {
  accepted: boolean;
}

export interface FileAccepted {
  accepted?: boolean;
  success?: boolean;
  url: string;
  file_id?: string;
}

export interface HealthResponse {
  status: string;
  service?: string;
  version?: string;
  environment?: string;
}

/**
 * The signed-in user, built from the OpenID Connect ID token / userinfo claims.
 */
export interface User {
  /** Identity-provider user id (OIDC `sub`). Zitadel ids are numeric strings. */
  id: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  picture?: string;
  locale?: string;
  /** Project role keys granted to the user (Zitadel `urn:zitadel:iam:org:project:roles`) */
  roles?: string[];
  /** Organization the user belongs to (Zitadel `urn:zitadel:iam:user:resourceowner:id`) */
  org_id?: string;
  /** Seconds since epoch, from the `updated_at` claim */
  updated_at?: number;
  /** All raw claims, for anything not mapped above */
  claims?: Record<string, unknown>;
}

export type AuthError = {
  code?: number;
  status?: number;
  error_code?: string;
  msg: string;
  details?: Record<string, unknown>;
  request_id?: string;
};

export interface Session {
  access_token: string;
  /** Present when the `offline_access` scope was granted */
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  scope?: string;
  user: User;
}

export interface AuthOptions {
  /** OIDC issuer URL, e.g. "https://auth.example.com" (dev: "http://auth.localhost:8000") */
  issuer?: string;
  /** Client id of the OIDC app (OGNA core creates "ogna-web"; see `make auth-info`) */
  clientId?: string;
  /** Where the identity provider sends users back after login. Defaults to `<origin>/auth/callback` */
  redirectUri?: string;
  /** Where users land after logout. Defaults to `<origin>/` */
  postLogoutRedirectUri?: string;
  /** Space-separated scopes. Defaults to "openid profile email offline_access" */
  scopes?: string;
  /** How to navigate the browser (defaults to `window.location.assign`); useful for tests and native apps */
  navigate?: (url: string) => void;
}

export interface RedirectOptions {
  /** Path or URL to return to after the callback is handled (returned by `handleRedirectCallback`) */
  returnTo?: string;
  /** Pre-fill the login name on the identity provider's page */
  loginHint?: string;
  /** OIDC `prompt` (e.g. "login", "select_account", "create") */
  prompt?: string;
  /** Extra authorization request parameters */
  extraParams?: Record<string, string>;
}

export interface CallbackResult {
  session: Session;
  /** The `returnTo` passed to `signInWithRedirect`, if any */
  returnTo: string | null;
}

export interface LogoutOptions {
  /** Also end the identity-provider session by redirecting to its logout page. Defaults to true in browsers. */
  redirect?: boolean;
  /** Override where the identity provider sends the user after logout */
  postLogoutRedirectUri?: string;
}

export type ApiResult<T = unknown> = {
  data: T | null;
  error: AuthError | null;
};

export type StorageStrategy =
  | "cookie"
  | "localStorage"
  | "sessionStorage"
  | "memory";

export type AuthChangeEvent =
  | "INITIAL_SESSION"
  | "SIGNED_IN"
  | "SIGNED_OUT"
  | "TOKEN_REFRESHED"
  | "USER_UPDATED";

export type AuthChangeCallback = (
  event: AuthChangeEvent,
  session: Session | null
) => void;

export interface CookieOptions {
  /** Cookie path. Defaults to "/" */
  path?: string;
  /** SameSite policy. Defaults to "Lax" */
  sameSite?: "Strict" | "Lax" | "None";
  /** Force Secure flag. Defaults to auto-detecting HTTPS */
  secure?: boolean;
  /** Optional cookie domain */
  domain?: string;
}

export interface OgnaClientOptions {
  /**
   * Where session tokens should be persisted in the browser.
   * - "cookie" (default): Stores session in SameSite cookie + localStorage token for backward compatibility
   * - "localStorage": Stores session in window.localStorage only
   * - "sessionStorage": Stores session in window.sessionStorage only (cleared when tab closes)
   * - "memory": Keeps tokens in memory only (most secure against XSS token theft)
   */
  storageStrategy?: StorageStrategy;
  /**
   * Automatically refresh expired access tokens using the refresh_token before requests
   * and retry once on 401 Unauthorized responses. Defaults to true.
   */
  autoRefreshToken?: boolean;
  /**
   * Persist session across page reloads. Defaults to true.
   */
  persistSession?: boolean;
  /**
   * Default request timeout in milliseconds. Defaults to 30000 (30s). Set to 0 to disable.
   */
  timeoutMs?: number;
  /**
   * Custom headers to attach to every request.
   */
  headers?: Record<string, string>;
  /**
   * Cookie configuration when storageStrategy is "cookie".
   */
  cookieOptions?: CookieOptions;
  /**
   * Custom fetch implementation (useful for SSR, testing, or custom interceptors).
   */
  fetch?: typeof fetch;
  /**
   * OpenID Connect settings for signing users in through the identity provider (Zitadel).
   */
  auth?: AuthOptions;
}

export interface RequestOptions extends RequestInit {
  isBlob?: boolean;
  /** Query parameters to safely encode and append to the URL */
  params?: Record<string, string | number | boolean | undefined | null>;
  /** Per-request timeout override in milliseconds */
  timeoutMs?: number;
  /** Internal flag to prevent infinite retry loops on 401 */
  _isRetry?: boolean;
  /** Skip attaching Authorization header (e.g. for public auth endpoints) */
  skipAuth?: boolean;
}

export function isAuthError(err: unknown): err is AuthError {
  return (
    typeof err === "object" &&
    err !== null &&
    "msg" in err &&
    typeof (err as AuthError).msg === "string"
  );
}

/**
 * INTERNAL SECURITY & URL HELPERS
 */
const TOKEN_STORAGE_KEY = "ogna_token";
const SESSION_STORAGE_KEY = "ogna_session";
const OIDC_TRANSACTION_KEY = "ogna_oidc_tx";
const OIDC_TRANSACTION_MAX_AGE_MS = 10 * 60 * 1000;
const DEFAULT_SCOPES = "openid profile email offline_access";
const EXPIRY_MARGIN_SECONDS = 30;

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
}

interface OidcTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  returnTo: string | null;
  createdAt: number;
}

interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return globalThis
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecodeToString(input: string): string {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = globalThis.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || typeof globalThis.atob !== "function") return null;
    const parsed = JSON.parse(base64UrlDecodeToString(parts[1]));
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

function decodeJwtExp(token: string): number | null {
  const payload = decodeJwtPayload(token);
  return payload && typeof payload.exp === "number" ? payload.exp : null;
}

function getWebCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function" || !c.subtle) {
    throw new Error(
      "OIDC sign-in needs the Web Crypto API (available on https:// pages, localhost, and Node 20+)"
    );
  }
  return c;
}

function randomUrlSafeString(byteLength: number = 32): string {
  const bytes = new Uint8Array(byteLength);
  getWebCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await getWebCrypto().subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function userFromClaims(claims: Record<string, unknown>): User {
  const str = (key: string): string | undefined =>
    typeof claims[key] === "string" ? (claims[key] as string) : undefined;
  const rolesClaim = claims["urn:zitadel:iam:org:project:roles"];
  const roles =
    rolesClaim && typeof rolesClaim === "object"
      ? Object.keys(rolesClaim as Record<string, unknown>).sort()
      : undefined;
  return {
    id: String(claims.sub ?? ""),
    email: str("email"),
    email_verified:
      typeof claims.email_verified === "boolean" ? claims.email_verified : undefined,
    name: str("name"),
    given_name: str("given_name"),
    family_name: str("family_name"),
    preferred_username: str("preferred_username"),
    picture: str("picture"),
    locale: str("locale"),
    roles,
    org_id: str("urn:zitadel:iam:user:resourceowner:id"),
    updated_at: typeof claims.updated_at === "number" ? claims.updated_at : undefined,
    claims,
  };
}

function resolveEnv(...names: string[]): string | undefined {
  try {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } })
      .process?.env;
    if (!env) return undefined;
    for (const name of names) {
      if (env[name]) return env[name];
    }
  } catch {
    // Ignore env access errors in restricted runtimes
  }
  return undefined;
}

function computeExpiresAt(session: Session): number {
  if (typeof session.expires_at === "number" && session.expires_at > 0) {
    return session.expires_at;
  }
  const jwtExp = decodeJwtExp(session.access_token);
  if (jwtExp) {
    return jwtExp;
  }
  const expiresIn =
    typeof session.expires_in === "number" && session.expires_in > 0
      ? session.expires_in
      : 3600;
  return Math.floor(Date.now() / 1000) + expiresIn;
}

function isValidSessionObject(value: unknown): value is Session {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.access_token === "string" &&
    candidate.access_token.length > 0 &&
    (candidate.refresh_token === undefined ||
      typeof candidate.refresh_token === "string")
  );
}

function encodePathSegment(segment: string, label: string): string {
  const trimmed = segment.trim();
  if (!trimmed || trimmed === "." || trimmed === ".." || trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error(`Invalid ${label}: path traversal or empty segment is not allowed`);
  }
  return encodeURIComponent(trimmed);
}

function resolveDefaultBaseUrl(): string {
  // Check common frontend framework env vars safely without requiring @types/node
  try {
    const globalWithProcess = globalThis as {
      process?: { env?: Record<string, string | undefined> };
    };
    const env = globalWithProcess.process?.env;
    if (env) {
      const envUrl =
        env.NEXT_PUBLIC_OGNA_URL ||
        env.NEXT_PUBLIC_API_URL ||
        env.VITE_OGNA_URL ||
        env.VITE_API_URL ||
        env.REACT_APP_OGNA_URL ||
        env.OGNA_URL;
      if (envUrl) return envUrl;
    }
  } catch {
    // Ignore env access errors in restricted runtimes
  }

  if (typeof window !== "undefined" && window.location?.origin) {
    return window.location.origin;
  }

  return "http://localhost:8000";
}

function normalizeBaseUrl(rawUrl?: string): string {
  const target = (rawUrl && rawUrl.trim()) || resolveDefaultBaseUrl();
  const stripped = target.replace(/\/+$/, "");
  // Validate URL scheme to prevent javascript: or data: injection
  if (!/^https?:\/\//i.test(stripped)) {
    throw new Error(
      `Invalid OgnaClient baseUrl "${rawUrl}". Must start with http:// or https://`
    );
  }
  return stripped;
}

function isSameOriginUrl(baseUrl: string, requestUrl: string): boolean {
  try {
    const base = new URL(baseUrl);
    const target = new URL(requestUrl, baseUrl);
    return base.origin === target.origin;
  } catch {
    return false;
  }
}

function buildUrlWithParams(
  url: string,
  params?: Record<string, string | number | boolean | undefined | null>
): string {
  if (!params) return url;
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null
  );
  if (entries.length === 0) return url;

  const searchParams = new URLSearchParams();
  for (const [key, value] of entries) {
    searchParams.append(key, String(value));
  }
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}${searchParams.toString()}`;
}

/**
 * BASE MODULE
 */
abstract class OgnaModule {
  constructor(protected root: OgnaClient) {}

  protected async request<T>(
    method: string,
    url: string,
    body?: unknown,
    init: RequestOptions = {}
  ): Promise<ApiResult<T>> {
    const {
      isBlob,
      params,
      timeoutMs = this.root.options.timeoutMs ?? 30000,
      _isRetry = false,
      skipAuth = false,
      ...fetchOptions
    } = init;

    const finalUrl = buildUrlWithParams(url, params);

    // Proactively refresh expired token before making an authenticated request
    if (
      !skipAuth &&
      this.root.options.autoRefreshToken !== false &&
      this.root.auth.session?.refresh_token &&
      this.root.auth.isTokenExpired()
    ) {
      await this.root.auth.refreshSession();
    }

    const token = !skipAuth ? this.root.auth.getToken() : null;
    const shouldAttachAuth =
      Boolean(token) && isSameOriginUrl(this.root.baseUrl, finalUrl);

    const headers: Record<string, string> = {
      ...this.root.options.headers,
      ...(shouldAttachAuth ? { Authorization: `Bearer ${token}` } : {}),
      ...(fetchOptions.headers as Record<string, string>),
    };

    let finalBody: BodyInit | null | undefined;

    if (typeof FormData !== "undefined" && body instanceof FormData) {
      finalBody = body;
      // Do NOT set Content-Type for FormData; runtime sets multipart boundary
    } else if (typeof Blob !== "undefined" && body instanceof Blob) {
      finalBody = body;
    } else if (
      typeof URLSearchParams !== "undefined" &&
      body instanceof URLSearchParams
    ) {
      // OAuth endpoints (token, revoke) take form-encoded bodies
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      finalBody = body.toString();
    } else if (body !== undefined && body !== null) {
      if (!headers["Content-Type"] && !headers["content-type"]) {
        headers["Content-Type"] = "application/json";
      }
      finalBody = JSON.stringify(body);
    }

    const controller =
      typeof AbortController !== "undefined" ? new AbortController() : null;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    if (controller && timeoutMs > 0 && !fetchOptions.signal) {
      timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    }

    const fetchFn = this.root.options.fetch ?? fetch;

    try {
      const res = await fetchFn(finalUrl, {
        ...fetchOptions,
        method,
        headers,
        body: finalBody,
        signal: fetchOptions.signal ?? controller?.signal,
      });

      if (timeoutId) clearTimeout(timeoutId);

      // Automatic retry once on 401 Unauthorized if refresh_token is available
      if (
        res.status === 401 &&
        !skipAuth &&
        !_isRetry &&
        this.root.options.autoRefreshToken !== false &&
        this.root.auth.session?.refresh_token
      ) {
        const refreshResult = await this.root.auth.refreshSession();
        if (refreshResult.data) {
          return this.request<T>(method, url, body, {
            ...init,
            _isRetry: true,
          });
        }
      }

      // 1. Handle Error States
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        const message =
          errorData.msg ||
          errorData.message ||
          errorData.error_description ||
          (typeof errorData.detail === "string" ? errorData.detail : null) ||
          `Request failed: ${res.status}`;

        return {
          data: null,
          error: {
            code: errorData.code ?? res.status,
            status: res.status,
            error_code:
              errorData.error_code ??
              (typeof errorData.error === "string" ? errorData.error : undefined),
            msg: message,
            details: errorData.details,
            request_id: errorData.request_id,
          },
        };
      }

      // 2. Handle Blob/Binary data (for downloads)
      if (isBlob) {
        const blob = await res.blob();
        return { data: blob as unknown as T, error: null };
      }

      // 3. Handle "No Content" (204 or empty body)
      const contentLength = res.headers.get("content-length");
      if (res.status === 204 || contentLength === "0") {
        return { data: {} as T, error: null };
      }

      // 4. Parse JSON safely
      const text = await res.text();
      if (!text) {
        return { data: {} as T, error: null };
      }
      const json = JSON.parse(text) as T;
      return { data: json, error: null };
    } catch (err) {
      if (timeoutId) clearTimeout(timeoutId);
      const isAbort =
        err instanceof Error &&
        (err.name === "AbortError" || err.message.includes("aborted"));
      return {
        data: null,
        error: {
          msg: isAbort
            ? `Request timed out after ${timeoutMs}ms`
            : err instanceof Error
              ? err.message
              : "Network error",
          error_code: isAbort ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
        },
      };
    }
  }
}

/**
 * AUTH SUB-CLASS
 */
export class AuthClient extends OgnaModule {
  private _session: Session | null = null;
  private _refreshPromise: Promise<ApiResult<Session>> | null = null;
  private _listeners: Set<AuthChangeCallback> = new Set();
  private _discovery: Promise<OidcDiscovery> | null = null;
  private _memoryTransaction: string | null = null;

  constructor(root: OgnaClient) {
    super(root);
    if (
      typeof window !== "undefined" &&
      this.root.options.persistSession !== false
    ) {
      this.loadPersistedSession();
    }
  }

  get session(): Session | null {
    return this._session;
  }

  private get strategy(): StorageStrategy {
    return this.root.options.storageStrategy ?? "cookie";
  }

  private notifyListeners(event: AuthChangeEvent, session: Session | null): void {
    for (const listener of this._listeners) {
      try {
        listener(event, session);
      } catch {
        // Ignore individual listener errors so other subscribers still run
      }
    }
  }

  /**
   * Subscribe to authentication state changes (login, logout, token refresh, user update).
   * Immediately invokes the callback with the current `INITIAL_SESSION`.
   */
  onAuthStateChange(callback: AuthChangeCallback): { unsubscribe: () => void } {
    this._listeners.add(callback);
    try {
      callback("INITIAL_SESSION", this._session);
    } catch {
      // Ignore callback error
    }
    return {
      unsubscribe: () => {
        this._listeners.delete(callback);
      },
    };
  }

  private getCookieValue(name: string): string | null {
    if (typeof document === "undefined" || !document.cookie) return null;
    const prefix = `${name}=`;
    const cookies = document.cookie.split(";");
    for (const raw of cookies) {
      const row = raw.trim();
      if (row.startsWith(prefix)) {
        // Slice after the first '=' so base64/JSON values containing '=' are preserved
        return row.slice(prefix.length);
      }
    }
    return null;
  }

  private loadPersistedSession(): void {
    if (typeof window === "undefined") return;
    const strategy = this.strategy;

    if (strategy === "memory") return;

    try {
      if (strategy === "sessionStorage") {
        const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (isValidSessionObject(parsed)) {
            this._session = {
              ...parsed,
              expires_at: computeExpiresAt(parsed),
            };
          }
        }
        return;
      }

      if (strategy === "localStorage") {
        const raw = window.localStorage.getItem(SESSION_STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (isValidSessionObject(parsed)) {
            this._session = {
              ...parsed,
              expires_at: computeExpiresAt(parsed),
            };
            window.localStorage.setItem(
              TOKEN_STORAGE_KEY,
              this._session.access_token
            );
          }
        }
        return;
      }

      // Default "cookie" strategy (also checks localStorage fallback)
      const encodedSession = this.getCookieValue(SESSION_STORAGE_KEY);
      if (encodedSession) {
        const parsed = JSON.parse(decodeURIComponent(encodedSession));
        if (isValidSessionObject(parsed)) {
          this._session = {
            ...parsed,
            expires_at: computeExpiresAt(parsed),
          };
          if (!window.localStorage.getItem(TOKEN_STORAGE_KEY)) {
            window.localStorage.setItem(
              TOKEN_STORAGE_KEY,
              this._session.access_token
            );
          }
          return;
        }
      }

      // Fallback to localStorage session if cookie wasn't present
      const storedSession = window.localStorage.getItem(SESSION_STORAGE_KEY);
      if (storedSession) {
        const parsed = JSON.parse(storedSession);
        if (isValidSessionObject(parsed)) {
          this._session = {
            ...parsed,
            expires_at: computeExpiresAt(parsed),
          };
        }
      }
    } catch {
      this.clearPersistedSession();
    }
  }

  private persistSession(session: Session): void {
    const normalized: Session = {
      ...session,
      expires_at: computeExpiresAt(session),
    };
    this._session = normalized;

    if (
      typeof window === "undefined" ||
      this.root.options.persistSession === false ||
      this.strategy === "memory"
    ) {
      return;
    }

    try {
      if (this.strategy === "sessionStorage") {
        window.sessionStorage.setItem(
          SESSION_STORAGE_KEY,
          JSON.stringify(normalized)
        );
        window.sessionStorage.setItem(
          TOKEN_STORAGE_KEY,
          normalized.access_token
        );
        return;
      }

      if (this.strategy === "localStorage") {
        window.localStorage.setItem(
          SESSION_STORAGE_KEY,
          JSON.stringify(normalized)
        );
        window.localStorage.setItem(TOKEN_STORAGE_KEY, normalized.access_token);
        return;
      }

      // Default "cookie" strategy
      const maxAge = normalized.expires_in || 3600;
      const cookieOpts = this.root.options.cookieOptions;
      const path = cookieOpts?.path ?? "/";
      const sameSite = cookieOpts?.sameSite ?? "Lax";
      const isHttps =
        cookieOpts?.secure ??
        (typeof window !== "undefined" &&
          window.location?.protocol === "https:");
      const secureAttr = isHttps || sameSite === "None" ? "; Secure" : "";
      const domainAttr = cookieOpts?.domain
        ? `; Domain=${cookieOpts.domain}`
        : "";

      if (typeof document !== "undefined") {
        document.cookie = `${TOKEN_STORAGE_KEY}=${encodeURIComponent(
          normalized.access_token
        )}; Path=${path}; Max-Age=${maxAge}; SameSite=${sameSite}${domainAttr}${secureAttr}`;
        document.cookie = `${SESSION_STORAGE_KEY}=${encodeURIComponent(
          JSON.stringify(normalized)
        )}; Path=${path}; Max-Age=${maxAge}; SameSite=${sameSite}${domainAttr}${secureAttr}`;
      }
      window.localStorage.setItem(TOKEN_STORAGE_KEY, normalized.access_token);
      window.localStorage.setItem(
        SESSION_STORAGE_KEY,
        JSON.stringify(normalized)
      );
    } catch {
      // Storage quota or restricted iframe environment; memory session remains active
    }
  }

  private clearPersistedSession(): void {
    this._session = null;
    if (typeof window === "undefined") return;

    try {
      const path = this.root.options.cookieOptions?.path ?? "/";
      const domainAttr = this.root.options.cookieOptions?.domain
        ? `; Domain=${this.root.options.cookieOptions.domain}`
        : "";
      if (typeof document !== "undefined") {
        document.cookie = `${TOKEN_STORAGE_KEY}=; Path=${path}${domainAttr}; Max-Age=0`;
        document.cookie = `${SESSION_STORAGE_KEY}=; Path=${path}${domainAttr}; Max-Age=0`;
      }
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
      window.localStorage.removeItem(SESSION_STORAGE_KEY);
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {
      // Ignore storage access errors during cleanup
    }
  }

  // ---------------------------------------------------------------------------
  // OpenID Connect (Authorization Code + PKCE) against the identity provider
  // ---------------------------------------------------------------------------

  private get authOptions(): AuthOptions {
    return this.root.options.auth ?? {};
  }

  private get issuer(): string {
    const issuer =
      this.authOptions.issuer ||
      resolveEnv(
        "NEXT_PUBLIC_OGNA_AUTH_URL",
        "VITE_OGNA_AUTH_URL",
        "REACT_APP_OGNA_AUTH_URL",
        "OGNA_AUTH_URL"
      );
    if (!issuer) {
      throw new Error(
        "OgnaClient: set options.auth.issuer to your identity provider URL (e.g. http://auth.localhost:8000)"
      );
    }
    const stripped = issuer.trim().replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(stripped)) {
      throw new Error(`OgnaClient: invalid auth issuer "${issuer}"`);
    }
    return stripped;
  }

  private get clientId(): string {
    const clientId =
      this.authOptions.clientId ||
      resolveEnv(
        "NEXT_PUBLIC_OGNA_CLIENT_ID",
        "VITE_OGNA_CLIENT_ID",
        "REACT_APP_OGNA_CLIENT_ID",
        "OGNA_CLIENT_ID"
      );
    if (!clientId) {
      throw new Error(
        "OgnaClient: set options.auth.clientId (run `make auth-info` in ogna core to see it)"
      );
    }
    return clientId;
  }

  private browserOrigin(): string {
    if (typeof window !== "undefined" && window.location?.origin) {
      return window.location.origin;
    }
    return this.root.baseUrl;
  }

  private get redirectUri(): string {
    return this.authOptions.redirectUri ?? `${this.browserOrigin()}/auth/callback`;
  }

  private get postLogoutRedirectUri(): string {
    return this.authOptions.postLogoutRedirectUri ?? `${this.browserOrigin()}/`;
  }

  private navigate(url: string): void {
    if (this.authOptions.navigate) {
      this.authOptions.navigate(url);
      return;
    }
    if (typeof window !== "undefined" && window.location) {
      window.location.assign(url);
      return;
    }
    throw new Error("OgnaClient: no browser available; pass options.auth.navigate");
  }

  /** Fetches (once) and caches the identity provider's OIDC discovery document. */
  async getDiscovery(): Promise<OidcDiscovery> {
    if (!this._discovery) {
      const issuer = this.issuer;
      const fetchFn = this.root.options.fetch ?? fetch;
      this._discovery = (async () => {
        const res = await fetchFn(`${issuer}/.well-known/openid-configuration`, {
          headers: { Accept: "application/json" },
        });
        if (!res.ok) {
          throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
        }
        const doc = (await res.json()) as OidcDiscovery;
        if (!doc || doc.issuer?.replace(/\/+$/, "") !== issuer) {
          throw new Error(
            `OIDC discovery issuer mismatch: expected ${issuer}, got ${doc?.issuer}`
          );
        }
        if (!doc.authorization_endpoint || !doc.token_endpoint) {
          throw new Error("OIDC discovery document is missing required endpoints");
        }
        return doc;
      })();
      this._discovery.catch(() => {
        this._discovery = null;
      });
    }
    return this._discovery;
  }

  private saveTransaction(tx: OidcTransaction): void {
    const raw = JSON.stringify(tx);
    this._memoryTransaction = raw;
    try {
      if (typeof window !== "undefined" && window.sessionStorage) {
        window.sessionStorage.setItem(OIDC_TRANSACTION_KEY, raw);
      }
    } catch {
      // sessionStorage unavailable; in-memory copy is used (same page only)
    }
  }

  private takeTransaction(): OidcTransaction | null {
    let raw: string | null = null;
    try {
      if (typeof window !== "undefined" && window.sessionStorage) {
        raw = window.sessionStorage.getItem(OIDC_TRANSACTION_KEY);
        window.sessionStorage.removeItem(OIDC_TRANSACTION_KEY);
      }
    } catch {
      // ignore
    }
    raw = raw ?? this._memoryTransaction;
    this._memoryTransaction = null;
    if (!raw) return null;
    try {
      const tx = JSON.parse(raw) as OidcTransaction;
      if (Date.now() - tx.createdAt > OIDC_TRANSACTION_MAX_AGE_MS) return null;
      return tx;
    } catch {
      return null;
    }
  }

  /**
   * Builds the authorization URL (and stores the PKCE/state values needed by
   * `handleRedirectCallback`) without navigating. Most apps use `signInWithRedirect`.
   */
  async getAuthorizationUrl(options: RedirectOptions = {}): Promise<string> {
    const discovery = await this.getDiscovery();
    const codeVerifier = randomUrlSafeString(32);
    const tx: OidcTransaction = {
      state: randomUrlSafeString(16),
      nonce: randomUrlSafeString(16),
      codeVerifier,
      redirectUri: this.redirectUri,
      returnTo: options.returnTo ?? null,
      createdAt: Date.now(),
    };
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: tx.redirectUri,
      response_type: "code",
      scope: this.authOptions.scopes ?? DEFAULT_SCOPES,
      state: tx.state,
      nonce: tx.nonce,
      code_challenge: await pkceChallenge(codeVerifier),
      code_challenge_method: "S256",
    });
    if (options.prompt) params.set("prompt", options.prompt);
    if (options.loginHint) params.set("login_hint", options.loginHint);
    for (const [key, value] of Object.entries(options.extraParams ?? {})) {
      params.set(key, value);
    }
    this.saveTransaction(tx);
    const separator = discovery.authorization_endpoint.includes("?") ? "&" : "?";
    return `${discovery.authorization_endpoint}${separator}${params.toString()}`;
  }

  /** Sends the user to the identity provider's login page. */
  async signInWithRedirect(options: RedirectOptions = {}): Promise<void> {
    this.navigate(await this.getAuthorizationUrl(options));
  }

  /** Sends the user to the identity provider's registration page (`prompt=create`). */
  async signUpWithRedirect(options: RedirectOptions = {}): Promise<void> {
    this.navigate(await this.getAuthorizationUrl({ prompt: "create", ...options }));
  }

  /** True if `url` (default: current location) is an OIDC callback with a code or an error. */
  isRedirectCallback(url?: string): boolean {
    const target =
      url ?? (typeof window !== "undefined" ? window.location?.href : undefined);
    if (!target) return false;
    try {
      const params = new URL(target).searchParams;
      return params.has("state") && (params.has("code") || params.has("error"));
    } catch {
      return false;
    }
  }

  /**
   * Completes sign-in on the redirect URI: verifies `state`, exchanges the code
   * (with the PKCE verifier) for tokens, checks the ID token nonce, and stores the session.
   */
  async handleRedirectCallback(url?: string): Promise<ApiResult<CallbackResult>> {
    const target =
      url ?? (typeof window !== "undefined" ? window.location?.href : undefined);
    if (!target) {
      return { data: null, error: { msg: "No callback URL to handle" } };
    }

    let params: URLSearchParams;
    try {
      params = new URL(target).searchParams;
    } catch {
      return { data: null, error: { msg: "Invalid callback URL" } };
    }

    const tx = this.takeTransaction();
    const fail = (msg: string, error_code: string): ApiResult<CallbackResult> => ({
      data: null,
      error: { msg, error_code },
    });

    if (params.get("error")) {
      return fail(
        params.get("error_description") || params.get("error") || "Sign-in failed",
        params.get("error") || "oidc_error"
      );
    }
    if (!tx) {
      return fail("No sign-in in progress (or it expired); start again", "missing_transaction");
    }
    if (params.get("state") !== tx.state) {
      return fail("State mismatch; possible CSRF, sign-in aborted", "state_mismatch");
    }
    const code = params.get("code");
    if (!code) {
      return fail("Callback is missing the authorization code", "missing_code");
    }

    let discovery: OidcDiscovery;
    try {
      discovery = await this.getDiscovery();
    } catch (err) {
      return fail(err instanceof Error ? err.message : "OIDC discovery failed", "discovery_failed");
    }

    const tokens = await this.request<TokenResponse>(
      "POST",
      discovery.token_endpoint,
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: tx.redirectUri,
        client_id: this.clientId,
        code_verifier: tx.codeVerifier,
      }),
      { skipAuth: true, _isRetry: true }
    );
    if (!tokens.data) {
      return { data: null, error: tokens.error };
    }

    let user: User | null = null;
    if (tokens.data.id_token) {
      const claims = decodeJwtPayload(tokens.data.id_token);
      if (!claims || claims.nonce !== tx.nonce) {
        return fail("ID token nonce mismatch; sign-in aborted", "nonce_mismatch");
      }
      user = userFromClaims(claims);
    }

    const session = this.sessionFromTokens(tokens.data, user ?? { id: "" });
    this.persistSession(session);
    if (!user) {
      await this.fetchUser();
    }
    this.notifyListeners("SIGNED_IN", this._session);
    return {
      data: { session: this._session as Session, returnTo: tx.returnTo },
      error: null,
    };
  }

  private sessionFromTokens(tokens: TokenResponse, user: User, previous?: Session | null): Session {
    return {
      access_token: tokens.access_token,
      // Refresh tokens may or may not be rotated; keep the old one if none is returned
      refresh_token: tokens.refresh_token ?? previous?.refresh_token,
      id_token: tokens.id_token ?? previous?.id_token,
      expires_in: typeof tokens.expires_in === "number" ? tokens.expires_in : 3600,
      expires_at: undefined,
      token_type: tokens.token_type ?? "Bearer",
      scope: tokens.scope ?? previous?.scope,
      user,
    };
  }

  /**
   * Refreshes the current session using the stored `refresh_token`.
   * Concurrent calls share a single in-flight request so a rotated refresh token is never reused.
   */
  async refreshSession(refreshToken?: string): Promise<ApiResult<Session>> {
    if (this._refreshPromise) {
      return this._refreshPromise;
    }

    const tokenToUse = refreshToken ?? this._session?.refresh_token;
    if (!tokenToUse) {
      return {
        data: null,
        error: { msg: "No refresh token available", code: 401, status: 401 },
      };
    }

    this._refreshPromise = (async () => {
      try {
        let discovery: OidcDiscovery;
        try {
          discovery = await this.getDiscovery();
        } catch (err) {
          return {
            data: null,
            error: {
              msg: err instanceof Error ? err.message : "OIDC discovery failed",
              error_code: "discovery_failed",
            },
          };
        }

        const result = await this.request<TokenResponse>(
          "POST",
          discovery.token_endpoint,
          new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: tokenToUse,
            client_id: this.clientId,
          }),
          { skipAuth: true, _isRetry: true }
        );

        if (result.data && result.data.access_token) {
          const previous = this._session;
          let user = previous?.user ?? { id: "" };
          if (result.data.id_token) {
            const claims = decodeJwtPayload(result.data.id_token);
            if (claims) user = userFromClaims(claims);
          }
          this.persistSession(this.sessionFromTokens(result.data, user, previous));
          this.notifyListeners("TOKEN_REFRESHED", this._session);
          return { data: this._session as Session, error: null };
        }

        if (
          result.error &&
          (result.error.status === 400 ||
            result.error.status === 401 ||
            result.error.status === 403)
        ) {
          this.clearPersistedSession();
          this.notifyListeners("SIGNED_OUT", null);
        }
        return { data: null, error: result.error };
      } finally {
        this._refreshPromise = null;
      }
    })();

    return this._refreshPromise;
  }

  /**
   * Fetches the signed-in user's claims from the identity provider's userinfo
   * endpoint and updates the stored session user.
   */
  async fetchUser(): Promise<ApiResult<User>> {
    if (!this._session?.access_token) {
      return { data: null, error: { msg: "Not signed in", code: 401, status: 401 } };
    }
    let discovery: OidcDiscovery;
    try {
      discovery = await this.getDiscovery();
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "OIDC discovery failed" },
      };
    }
    if (!discovery.userinfo_endpoint) {
      return { data: null, error: { msg: "Identity provider has no userinfo endpoint" } };
    }
    const result = await this.request<Record<string, unknown>>(
      "GET",
      discovery.userinfo_endpoint,
      undefined,
      {
        skipAuth: true,
        _isRetry: true,
        headers: { Authorization: `Bearer ${this._session.access_token}` },
      }
    );
    if (!result.data) {
      return { data: null, error: result.error };
    }
    const user = userFromClaims(result.data);
    if (this._session) {
      this.persistSession({ ...this._session, user });
      this.notifyListeners("USER_UPDATED", this._session);
    }
    return { data: user, error: null };
  }

  /**
   * Signs out: revokes the refresh and access tokens, clears the local session and,
   * by default in browsers, redirects to the identity provider to end its session too.
   */
  async logout(options: LogoutOptions = {}): Promise<ApiResult<Record<string, never>>> {
    const session = this._session;
    let error: AuthError | null = null;
    let endSessionUrl: string | null = null;

    if (session) {
      try {
        const discovery = await this.getDiscovery();
        if (discovery.revocation_endpoint) {
          const revoke = (token: string, hint: string) =>
            this.request<Record<string, never>>(
              "POST",
              discovery.revocation_endpoint as string,
              new URLSearchParams({ token, token_type_hint: hint, client_id: this.clientId }),
              { skipAuth: true, _isRetry: true }
            );
          const results = await Promise.all([
            session.refresh_token ? revoke(session.refresh_token, "refresh_token") : null,
            revoke(session.access_token, "access_token"),
          ]);
          error = results.find((r) => r?.error)?.error ?? null;
        }
        if (discovery.end_session_endpoint) {
          const params = new URLSearchParams({
            client_id: this.clientId,
            post_logout_redirect_uri:
              options.postLogoutRedirectUri ?? this.postLogoutRedirectUri,
          });
          if (session.id_token) params.set("id_token_hint", session.id_token);
          endSessionUrl = `${discovery.end_session_endpoint}?${params.toString()}`;
        }
      } catch (err) {
        error = { msg: err instanceof Error ? err.message : "Logout failed" };
      }
    }

    this.clearPersistedSession();
    this.notifyListeners("SIGNED_OUT", null);

    const shouldRedirect =
      options.redirect ?? (typeof window !== "undefined" || Boolean(this.authOptions.navigate));
    if (shouldRedirect && endSessionUrl) {
      this.navigate(endSessionUrl);
    }
    return error ? { data: null, error } : { data: {}, error: null };
  }

  /**
   * Returns true if the current access token is expired (or within `bufferSeconds` of expiring).
   */
  isTokenExpired(bufferSeconds: number = EXPIRY_MARGIN_SECONDS): boolean {
    const token = this.getRawToken();
    if (!token) return true;

    const expiresAt = this._session?.expires_at ?? decodeJwtExp(token);
    if (!expiresAt) return false;

    const nowSeconds = Math.floor(Date.now() / 1000);
    return nowSeconds + bufferSeconds >= expiresAt;
  }

  private getRawToken(): string | null {
    if (this._session?.access_token) {
      return this._session.access_token;
    }
    if (typeof window === "undefined" || this.strategy === "memory") {
      return null;
    }
    try {
      if (this.strategy === "sessionStorage") {
        return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
      }
      return (
        window.localStorage.getItem(TOKEN_STORAGE_KEY) ||
        this.getCookieValue(TOKEN_STORAGE_KEY)
      );
    } catch {
      return null;
    }
  }

  getToken(): string | null {
    return this.getRawToken();
  }

  getUser(): User | null {
    return this._session?.user ?? null;
  }

  isLoggedIn(): boolean {
    const token = this.getRawToken();
    if (!token) return false;
    // If token is expired and we have no refresh token, user is no longer logged in
    if (this.isTokenExpired(0) && !this._session?.refresh_token) {
      return false;
    }
    return true;
  }

  setSession(session: Session | null): void {
    if (session) {
      this.persistSession(session);
      this.notifyListeners("SIGNED_IN", this._session);
    } else {
      this.clearPersistedSession();
      this.notifyListeners("SIGNED_OUT", null);
    }
  }
}

/**
 * STORAGE SUB-CLASS
 */
export class StorageClient extends OgnaModule {
  /**
   * Creates a new storage bucket.
   */
  async createBucket(
    name: string,
    isPublic: boolean = false
  ): Promise<ApiResult<SimpleResponse>> {
    return this.request<SimpleResponse>(
      "POST",
      `${this.root.baseUrl}/storage/v1/buckets`,
      { name: name.trim(), public: isPublic }
    );
  }

  /**
   * Lists all buckets accessible to the authenticated user.
   */
  async listBuckets(): Promise<ApiResult<Bucket[]>> {
    return this.request<Bucket[]>(
      "GET",
      `${this.root.baseUrl}/storage/v1/buckets`
    );
  }

  /**
   * Retrieves metadata for a specific bucket.
   */
  async getBucket(bucketName: string): Promise<ApiResult<Bucket>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      return this.request<Bucket>(
        "GET",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}`
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid bucketName" },
      };
    }
  }

  /**
   * Deletes a bucket and all of its objects.
   */
  async deleteBucket(bucketName: string): Promise<ApiResult<SimpleResponse>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      return this.request<SimpleResponse>(
        "DELETE",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}`
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid bucketName" },
      };
    }
  }

  /**
   * Lists all files in a bucket.
   */
  async listFiles(bucketName: string): Promise<ApiResult<FileObj[]>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      return this.request<FileObj[]>(
        "GET",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}/files`
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid bucketName" },
      };
    }
  }

  /**
   * Uploads a file to a bucket using multipart/form-data.
   */
  async uploadFile(
    bucketName: string,
    file: File | Blob,
    fileName?: string
  ): Promise<ApiResult<FileAccepted>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      const formData = new FormData();
      if (fileName) {
        formData.append("file", file, fileName);
      } else {
        formData.append("file", file);
      }

      return this.request<FileAccepted>(
        "POST",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}/files`,
        formData
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid bucketName" },
      };
    }
  }

  /**
   * Uploads or replaces a file at the specified `fileName` key in a bucket.
   */
  async replaceFile(
    bucketName: string,
    fileName: string,
    file: File | Blob
  ): Promise<ApiResult<FileAccepted>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      const safeFile = encodePathSegment(fileName, "fileName");
      const formData = new FormData();
      formData.append("file", file, fileName);

      return this.request<FileAccepted>(
        "PUT",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}/files/${safeFile}`,
        formData
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid path segment" },
      };
    }
  }

  /**
   * Downloads a file from a bucket as a binary `Blob`.
   */
  async downloadFile(
    bucketName: string,
    fileName: string
  ): Promise<ApiResult<Blob>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      const safeFile = encodePathSegment(fileName, "fileName");
      return this.request<Blob>(
        "GET",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}/files/${safeFile}`,
        null,
        { isBlob: true }
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid path segment" },
      };
    }
  }

  /**
   * Downloads a file and automatically triggers the browser's file save dialog.
   */
  async downloadFileToBrowser(
    bucketName: string,
    fileName: string,
    downloadAs?: string
  ): Promise<ApiResult<Blob>> {
    const result = await this.downloadFile(bucketName, fileName);
    if (
      result.data &&
      typeof window !== "undefined" &&
      typeof document !== "undefined"
    ) {
      const objectUrl = window.URL.createObjectURL(result.data);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.setAttribute("download", downloadAs || fileName);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
      window.URL.revokeObjectURL(objectUrl);
    }
    return result;
  }

  /**
   * Deletes a file from a bucket.
   */
  async deleteFile(
    bucketName: string,
    fileName: string
  ): Promise<ApiResult<SimpleResponse>> {
    try {
      const safeBucket = encodePathSegment(bucketName, "bucketName");
      const safeFile = encodePathSegment(fileName, "fileName");
      return this.request<SimpleResponse>(
        "DELETE",
        `${this.root.baseUrl}/storage/v1/buckets/${safeBucket}/files/${safeFile}`
      );
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Invalid path segment" },
      };
    }
  }

  /**
   * Checks the health of the Ogna Storage service.
   */
  async health(): Promise<ApiResult<HealthResponse>> {
    return this.request<HealthResponse>(
      "GET",
      `${this.root.baseUrl}/storage/v1/health`
    );
  }
}

/**
 * MAIN CLIENT
 */
export class OgnaClient {
  public readonly baseUrl: string;
  public readonly options: OgnaClientOptions;
  public auth: AuthClient;
  public storage: StorageClient;

  constructor(baseUrl?: string, options: OgnaClientOptions = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.options = {
      storageStrategy: "cookie",
      autoRefreshToken: true,
      persistSession: true,
      timeoutMs: 30000,
      ...options,
    };
    this.auth = new AuthClient(this);
    this.storage = new StorageClient(this);
  }

  get user(): User | null {
    return this.auth.getUser();
  }

  get session(): Session | null {
    return this.auth.session;
  }

  private buildApiUrl(path: string): string {
    const cleanPath = path.replace(/^\/+/, "");
    return `${this.baseUrl}/api/${cleanPath}`;
  }

  async get<T = unknown>(
    path: string,
    options?: RequestOptions
  ): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "GET",
      this.buildApiUrl(path),
      undefined,
      options
    );
  }

  async post<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "POST",
      this.buildApiUrl(path),
      body,
      options
    );
  }

  async put<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "PUT",
      this.buildApiUrl(path),
      body,
      options
    );
  }

  async patch<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "PATCH",
      this.buildApiUrl(path),
      body,
      options
    );
  }

  async delete<T = unknown>(
    path: string,
    options?: RequestOptions
  ): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "DELETE",
      this.buildApiUrl(path),
      undefined,
      options
    );
  }
}

/**
 * Convenience factory to initialize an `OgnaClient` instance.
 * If `baseUrl` is omitted, automatically detects `NEXT_PUBLIC_OGNA_URL`,
 * `VITE_OGNA_URL`, `VITE_API_URL`, `REACT_APP_OGNA_URL`, or `window.location.origin`.
 */
export function createOgnaClient(
  baseUrl?: string,
  options?: OgnaClientOptions
): OgnaClient {
  return new OgnaClient(baseUrl, options);
}
