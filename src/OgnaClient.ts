export interface User {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
  app_metadata?: any;
  user_metadata?: any;
  aud?: string;
  role?: string;
}

export interface Session {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  user: User;
}

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

type ApiResult<T = any> = {
  data: T | null;
  error: Error | any | null;
};

export class OgnaClient {
  private ognaBaseUrl: string;
  private authUrl: string;
  private session: Session | null = null;

  constructor(baseUrl: string) {
    this.ognaBaseUrl = baseUrl.replace(/\/+$/, ""); // strip trailing slash
    this.authUrl = `${this.ognaBaseUrl}/auth`;
  }

  async signup(email: string, password: string): Promise<ApiResult<Session>> {
    try {
      const response = await fetch(`${this.authUrl}/signup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.msg || errorData.error_description || "Signup failed"
        );
      }

      const data: Session = await response.json();
      this.session = data;
      return { data, error: null };
    } catch (error) {
      return { data: null, error };
    }
  }

  async login(
    email: string,
    password: string,
    remember: boolean = true
  ): Promise<ApiResult<Session>> {
    try {
      const response = await fetch(
        `${this.authUrl}/token?grant_type=password`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.msg || errorData.error_description || "Login failed"
        );
      }

      const data: Session = await response.json();
      this.session = data;
      return { data, error: null };
    } catch (error) {
      return { data: null, error };
    }
  }

  async logout(): Promise<ApiResult> {
    try {
      if (!this.session) {
        return { data: null, error: new Error("User not signed in") };
      }

      const response = await fetch(`${this.authUrl}/logout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.session.access_token}`,
        },
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.msg || "Logout failed");
      }

      this.session = null;
      return { data: {}, error: null };
    } catch (error) {
      return { data: null, error };
    }
  }

  async refreshSession(): Promise<ApiResult<Session>> {
    try {
      if (!this.session?.refresh_token) {
        throw new Error("No refresh token available");
      }

      const response = await fetch(
        `${this.authUrl}/token?grant_type=refresh_token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ refresh_token: this.session.refresh_token }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.msg || "Token refresh failed");
      }

      const data: Session = await response.json();
      this.session = data;
      return { data, error: null };
    } catch (error) {
      return { data: null, error };
    }
  }

  getUser(): User | null {
    return this.session?.user ?? null;
  }

  getToken(): string | null {
    return this.session?.access_token ?? null;
  }

  getSession(): Session | null {
    return this.session;
  }

  setSession(session: Session | null): void {
    this.session = session;
  }

  private async request<T>(
    method: HttpMethod,
    path: string,
    body?: any,
    init: RequestInit = {}
  ): Promise<ApiResult<T>> {
    try {
      const token = this.getToken();
      if (!token) throw new Error("No token available. User not logged in.");

      const url = `${this.ognaBaseUrl}/api/${
        path.startsWith("/") ? path : `${path}`
      }`;

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        ...(init.headers as Record<string, string>),
      };

      if (body) {
        headers["Content-Type"] = "application/json";
      }

      const res = await fetch(url, {
        ...init,
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });

      if (!res.ok) {
        const errorText = await res.text();
        return {
          data: null,
          error: new Error(
            `API ${method} ${url} failed: ${res.status} ${errorText}`
          ),
        };
      }

      const json = (await res.json()) as T;
      return { data: json, error: null };
    } catch (err: any) {
      return {
        data: null,
        error: err instanceof Error ? err : new Error(String(err)),
      };
    }
  }

  get<T>(path: string, init?: RequestInit) {
    return this.request<T>("GET", path, undefined, init);
  }

  post<T>(path: string, body: any, init?: RequestInit) {
    return this.request<T>("POST", path, body, init);
  }

  put<T>(path: string, body: any, init?: RequestInit) {
    return this.request<T>("PUT", path, body, init);
  }

  delete<T>(path: string, init?: RequestInit) {
    return this.request<T>("DELETE", path, undefined, init);
  }
}
