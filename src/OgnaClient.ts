/**
 * TYPES & INTERFACES
 */
export interface Bucket {
  owner: string;
  id: string;
  name: string;
}

export interface FileObj {
  last_modified: string;
  bucket_id: string;
  id: string;
  name: string;
}


interface OgnaRequestInit extends RequestInit {
  isBlob?: boolean;
}

export interface SimpleResponse {
  accepted: boolean;
}

export interface User {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
  aud?: string;
  role?: string;
}

export type AuthError = {
  code?: number;
  error_code?: string;
  msg?: string;
};

export interface Session {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  user: User;
}

interface FileAccepted {
  success: boolean;
  url: string;
}

export type ApiResult<T = unknown> = {
  data: T | null;
  error: AuthError | null;
};

export function isAuthError(err: unknown): err is AuthError {
  return typeof err === "object" && err !== null && "msg" in err;
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
    init: OgnaRequestInit = {}
  ): Promise<ApiResult<T>> {
    try {
      const token = this.root.auth.getToken();

      // Separate our custom flag from standard fetch options
      const { isBlob, ...fetchOptions } = init;

      const headers: Record<string, string> = {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(fetchOptions.headers as Record<string, string>),
      };

      let finalBody: BodyInit | null | undefined;

      if (body instanceof FormData) {
        finalBody = body;
        // Do NOT set Content-Type for FormData; browser handles boundary
      } else if (body !== undefined && body !== null) {
        headers["Content-Type"] = "application/json";
        finalBody = JSON.stringify(body);
      }

      const res = await fetch(url, {
        ...fetchOptions,
        method,
        headers,
        body: finalBody,
      });

      // 1. Handle Error States
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        return {
          data: null,
          error: {
            msg:
              errorData.msg ||
              errorData.error_description ||
              `Request failed: ${res.status}`,
          },
        };
      }

      // 2. Handle Blob/Binary data (for downloads)
      if (isBlob) {
        const blob = await res.blob();
        return { data: blob as unknown as T, error: null };
      }

      // 3. Handle "No Content" (204)
      const contentLength = res.headers.get("content-length");
      if (res.status === 204 || contentLength === "0") {
        return { data: {} as T, error: null };
      }

      // 4. Parse JSON
      const json = (await res.json()) as T;
      return { data: json, error: null };
    } catch (err) {
      return {
        data: null,
        error: { msg: err instanceof Error ? err.message : "Network error" },
      };
    }
  }
}

/**
 * AUTH SUB-CLASS
 */
export class AuthClient extends OgnaModule {
  private _session: Session | null = null;

  constructor(root: OgnaClient) {
    super(root);
    if (typeof window !== "undefined") {
      this.loadSessionFromCookies();
    }
  }

  get session(): Session | null {
    return this._session;
  }

  private loadSessionFromCookies(): void {
    const sessionCookie = document.cookie
      .split("; ")
      .find((row) => row.startsWith("ogna_session="));

    if (sessionCookie) {
      try {
        const sessionData = JSON.parse(
          decodeURIComponent(sessionCookie.split("=")[1])
        ) as Session;
        this._session = sessionData;
        if (!localStorage.getItem("ogna_token")) {
          localStorage.setItem("ogna_token", sessionData.access_token);
        }
      } catch {
        this.clearSessionCookies();
      }
    }
  }

  private saveSessionToCookies(session: Session): void {
    if (typeof window === "undefined") return;
    const maxAge = session.expires_in || 3600;
    const secure = "; Secure";
    document.cookie = `ogna_token=${session.access_token}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
    document.cookie = `ogna_session=${encodeURIComponent(
      JSON.stringify(session)
    )}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
    localStorage.setItem("ogna_token", session.access_token);
  }

  private clearSessionCookies(): void {
    if (typeof window === "undefined") return;
    document.cookie = "ogna_token=; Path=/; Max-Age=0";
    document.cookie = "ogna_session=; Path=/; Max-Age=0";
    localStorage.removeItem("ogna_token");
    this._session = null;
  }

  async login(email: string, password: string): Promise<ApiResult<Session>> {
    const result = await this.request<Session>(
      "POST",
      `${this.root.baseUrl}/auth/token?grant_type=password`,
      { email, password }
    );
    if (result.data) {
      this._session = result.data;
      this.saveSessionToCookies(result.data);
    }
    return result;
  }

  async signup(email: string, password: string): Promise<ApiResult<Session>> {
    const result = await this.request<Session>(
      "POST",
      `${this.root.baseUrl}/auth/signup`,
      { email, password }
    );
    if (result.data) {
      this._session = result.data;
      this.saveSessionToCookies(result.data);
    }
    return result;
  }

  async logout(): Promise<ApiResult<Record<string, never>>> {
    const result = await this.request<Record<string, never>>(
      "POST",
      `${this.root.baseUrl}/auth/logout`
    );
    this.clearSessionCookies();
    return result;
  }

  getToken(): string | null {
    return (
      this._session?.access_token ||
      (typeof window !== "undefined"
        ? localStorage.getItem("ogna_token")
        : null)
    );
  }

  getUser(): User | null {
    return this._session?.user ?? null;
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  setSession(session: Session | null): void {
    this._session = session;
    if (session) {
      this.saveSessionToCookies(session);
    } else {
      this.clearSessionCookies();
    }
  }
}

/**
 * STORAGE SUB-CLASS
 */
export class StorageClient extends OgnaModule {
  async createBucket(name: string): Promise<ApiResult<SimpleResponse>> {
    return this.request<SimpleResponse>(
      "POST",
      `${this.root.baseUrl}/storage/v1/buckets`,
      { name, public: false }
    );
  }

  async listBuckets(): Promise<ApiResult<Bucket[]>> {
    return this.request<Bucket[]>(
      "GET",
      `${this.root.baseUrl}/storage/v1/buckets`
    );
  }

  async listFiles(bucketId: string): Promise<ApiResult<FileObj[]>> {
    return this.request<FileObj[]>(
      "GET",
      `${this.root.baseUrl}/storage/v1/buckets/${bucketId}`
    );
  }

  async uploadFile(
    bucketName: string,
    file: File
  ): Promise<ApiResult<FileAccepted>> {
    const formData = new FormData();
    formData.append("file", file); // Must match FastAPI "file" parameter

    return this.request<FileAccepted>(
      "POST",
      `${this.root.baseUrl}/storage/v1/buckets/${bucketName}`,
      formData
    );
  }

  async downloadFile(
    bucketName: string,
    fileName: string
  ): Promise<ApiResult<Blob>> {
    return this.request<Blob>(
      "GET",
      `${this.root.baseUrl}/storage/v1/buckets/${bucketName}/${fileName}`,
      null,
      { isBlob: true }
    );
  }
}

/**
 * MAIN CLIENT
 */
export class OgnaClient {
  public readonly baseUrl: string;
  public auth: AuthClient;
  public storage: StorageClient;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.auth = new AuthClient(this);
    this.storage = new StorageClient(this);
  }

  get user(): User | null {
    return this.auth.getUser();
  }

  async get<T = unknown>(path: string): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "GET",
      `${this.baseUrl}/api/${path.replace(/^\/+/, "")}`
    );
  }

  async post<T = unknown>(path: string, body: unknown): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "POST",
      `${this.baseUrl}/api/${path.replace(/^\/+/, "")}`,
      body
    );
  }

  async put<T = unknown>(path: string, body: unknown): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "PUT",
      `${this.baseUrl}/api/${path.replace(/^\/+/, "")}`,
      body
    );
  }

  async patch<T = unknown>(path: string, body: unknown): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "PATCH",
      `${this.baseUrl}/api/${path.replace(/^\/+/, "")}`,
      body
    );
  }  

  async delete<T = unknown>(path: string): Promise<ApiResult<T>> {
    return this.auth["request"]<T>(
      "DELETE",
      `${this.baseUrl}/api/${path.replace(/^\/+/, "")}`
    );
  }
}
