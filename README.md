# @ogna/js — OgnaStack JavaScript & TypeScript SDK

A lightweight, zero-dependency TypeScript/JavaScript SDK for connecting UI applications (React, Next.js, Vite, Vue, Svelte) to [OgnaStack Core](https://github.com/ognastack/core).

---

## Features

- **Zero-Config Setup**: Auto-detects `NEXT_PUBLIC_OGNA_URL`, `VITE_OGNA_URL`, `VITE_API_URL`, `REACT_APP_OGNA_URL`, or `window.location.origin`.
- **Authentication (`client.auth`)**:
  - **OpenID Connect sign-in** against OgnaStack's identity provider (Zitadel): Authorization Code + PKCE redirect flow with `state` and `nonce` checks, sign-up (`prompt=create`), logout with token revocation and provider session end, `fetchUser` (userinfo), and reactive `onAuthStateChange` subscriptions.
  - **Automatic Token Refresh**: Proactively refreshes expired access tokens using the `refresh_token` (with concurrent request deduplication) and retries once on `401 Unauthorized`.
  - **Configurable Token Security**: Choose between `"cookie"`, `"localStorage"`, `"sessionStorage"`, or `"memory"` (XSS-resistant in-memory tokens).
- **Storage (`client.storage`)**:
  - Create, list, inspect, and delete buckets.
  - Upload, replace, list, download (`Blob` or direct browser save via `downloadFileToBrowser`), and delete files with built-in path-traversal protection.
- **API Gateway Client (`client.get`, `post`, `put`, `patch`, `delete`)**:
  - Automatically attaches `Authorization: Bearer <token>` only to same-origin gateway requests.
  - Built-in query parameter encoding (`params`) and request timeouts (`timeoutMs`).
- **Dual ESM & CJS + Full TypeScript Declarations**: Works out of the box with Vite, Next.js App/Pages Router, Webpack, and Node.js.

---

## Installation

```bash
npm install @ogna/js
```

---

## Quick Start

### 1. Initialize the Client

```ts
// lib/ogna.ts
import { createOgnaClient } from "@ogna/js";

// Automatically reads NEXT_PUBLIC_OGNA_URL / VITE_OGNA_URL / VITE_API_URL if baseUrl is omitted
export const ogna = createOgnaClient(import.meta.env.VITE_API_URL, {
  storageStrategy: "localStorage", // "cookie" | "localStorage" | "sessionStorage" | "memory"
  autoRefreshToken: true,          // Automatically refresh expired access tokens
  timeoutMs: 30000,                // 30s request timeout
  auth: {
    issuer: import.meta.env.VITE_OGNA_AUTH_URL,      // e.g. http://auth.localhost:8000
    clientId: import.meta.env.VITE_OGNA_CLIENT_ID,   // `make auth-info` in ogna core
    redirectUri: `${window.location.origin}/auth/callback`, // must be in OGNA_OIDC_REDIRECT_URIS
  },
});
```

Users sign in on the identity provider's hosted (brandable) login page, so your app never handles passwords. The redirect URI must be registered in OgnaStack core (`OGNA_OIDC_REDIRECT_URIS`; the defaults `http://localhost:3000/auth/callback` and `http://localhost:5173/auth/callback` match the SDK's default `<origin>/auth/callback`).

> In Next.js, read `process.env.NEXT_PUBLIC_*` literally (as above) so the values are inlined into the browser bundle.

### 2. React `AuthProvider` with `onAuthStateChange`

```tsx
// contexts/AuthContext.tsx
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { OgnaClient, Session, User } from "@ogna/js";

interface AuthContextValue {
  client: OgnaClient;
  user: User | null;
  session: Session | null;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const OgnaAuthProvider = ({
  baseUrl,
  children,
}: {
  baseUrl?: string;
  children: React.ReactNode;
}) => {
  const client = useMemo(
    () =>
      new OgnaClient(baseUrl, {
        storageStrategy: "localStorage",
        auth: {
          issuer: process.env.NEXT_PUBLIC_OGNA_AUTH_URL,
          clientId: process.env.NEXT_PUBLIC_OGNA_CLIENT_ID,
        },
      }),
    [baseUrl]
  );
  const [session, setSession] = useState<Session | null>(client.auth.session);

  useEffect(() => {
    const { unsubscribe } = client.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
    });
    return () => unsubscribe();
  }, [client]);

  const value = useMemo(
    () => ({
      client,
      session,
      user: session?.user ?? null,
      isAuthenticated: client.auth.isLoggedIn(),
    }),
    [client, session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useOgna = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useOgna must be used within an OgnaAuthProvider");
  }
  return ctx;
};
```

### 3. Calling Auth, API, and Storage Endpoints

```tsx
import React, { useState } from "react";
import { useOgna } from "./contexts/AuthContext";

export default function Todos() {
  const { client, user, isAuthenticated } = useOgna();
  const [todos, setTodos] = useState<{ id: string; title: string }[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = () => client.auth.signInWithRedirect({ returnTo: "/todos" });
  const handleSignup = () => client.auth.signUpWithRedirect({ returnTo: "/todos" });

  const loadTodos = async () => {
    const { data, error } = await client.get<{ id: string; title: string }[]>("/todos", {
      params: { limit: 20 },
    });
    if (error) setError(error.msg);
    if (data) setTodos(data);
  };

  if (!isAuthenticated) {
    return (
      <div>
        <h2>Welcome</h2>
        <button onClick={handleLogin}>Sign in</button>
        <button onClick={handleSignup}>Create account</button>
        {error && <p style={{ color: "red" }}>{error}</p>}
      </div>
    );
  }

  return (
    <div>
      <h2>Welcome {user?.email}</h2>
      <button onClick={() => client.auth.logout()}>Logout</button> {/* revokes tokens, ends the provider session */}
      <button onClick={loadTodos}>Load Todos</button>
      <ul>
        {todos.map((t) => (
          <li key={t.id}>{t.title}</li>
        ))}
      </ul>
    </div>
  );
}
```

### 4. Handle the redirect callback

Render this on your redirect URI (e.g. `/auth/callback`). It verifies `state`, exchanges the code with the PKCE verifier, checks the ID token `nonce`, and stores the session.

```tsx
// app/auth/callback/page.tsx (Next.js) or a route in your router
"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useOgna } from "@/contexts/AuthContext";

export default function AuthCallback() {
  const { client } = useOgna();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const handled = useRef(false); // React StrictMode runs effects twice; the code is single-use

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;
    client.auth.handleRedirectCallback().then(({ data, error }) => {
      if (error) setError(error.msg);
      else router.replace(data?.returnTo ?? "/");
    });
  }, [client, router]);

  return error ? <p>Sign-in failed: {error}</p> : <p>Signing you in…</p>;
}
```

### Auth API Reference

| Method | Description |
|--------|-------------|
| `auth.signInWithRedirect({ returnTo?, loginHint?, prompt?, extraParams? })` | Go to the identity provider's login page |
| `auth.signUpWithRedirect(options?)` | Same, opening the registration page (`prompt=create`) |
| `auth.getAuthorizationUrl(options?)` | Build the login URL without navigating (custom navigation, popups) |
| `auth.isRedirectCallback(url?)` | `true` if the URL carries `code`/`error` + `state` |
| `auth.handleRedirectCallback(url?)` | Finish sign-in; returns `{ session, returnTo }` |
| `auth.refreshSession()` | Refresh tokens now (normally automatic) |
| `auth.fetchUser()` | Reload the user from the userinfo endpoint |
| `auth.logout({ redirect?, postLogoutRedirectUri? })` | Revoke tokens, clear the session, and (in browsers) end the provider session |
| `auth.onAuthStateChange(cb)` | `INITIAL_SESSION`, `SIGNED_IN`, `TOKEN_REFRESHED`, `USER_UPDATED`, `SIGNED_OUT` |
| `auth.getToken()`, `auth.getUser()`, `auth.isLoggedIn()`, `auth.setSession()` | Synchronous helpers |

`User` is built from OIDC claims: `id` (the provider's user id, a string), `email`, `email_verified`, `name`, `given_name`, `family_name`, `preferred_username`, `picture`, `roles` (project roles), `org_id`, plus all raw `claims`.

### Migrating from 0.1.x (GoTrue)

OgnaStack core now uses Zitadel instead of GoTrue, so password-based calls are gone:

| 0.1.x | 0.2.x |
|-------|-------|
| `auth.login(email, password)` | `auth.signInWithRedirect()` + `auth.handleRedirectCallback()` on your redirect URI |
| `auth.signup(email, password, data)` | `auth.signUpWithRedirect()` |
| `auth.logout()` (`POST /auth/logout`) | `auth.logout()` (revokes tokens and ends the provider session; pass `{ redirect: false }` to stay on the page) |
| `auth.fetchUser()` (`GET /auth/user`) | `auth.fetchUser()` (OIDC userinfo) |
| `User.email: string`, `created_at`, `app_metadata`, `user_metadata` | `User.email?: string`, OIDC claims (`claims` has everything) |
| — | `options.auth = { issuer, clientId, redirectUri?, postLogoutRedirectUri?, scopes? }` |

---

## Storage API Reference

```ts
// Create a bucket
await client.storage.createBucket("avatars", false);

// List all buckets
const { data: buckets } = await client.storage.listBuckets();

// Upload a file
await client.storage.uploadFile("avatars", fileInput);

// Replace an existing file
await client.storage.replaceFile("avatars", "profile.png", fileInput);

// List files in a bucket
const { data: files } = await client.storage.listFiles("avatars");

// Download a file as a Blob
const { data: blob } = await client.storage.downloadFile("avatars", "profile.png");

// Download and trigger browser Save-As dialog automatically
await client.storage.downloadFileToBrowser("avatars", "profile.png");

// Delete a file or bucket
await client.storage.deleteFile("avatars", "profile.png");
await client.storage.deleteBucket("avatars");
```

---

## Security Features

- **Same-Origin Bearer Token Protection**: `Authorization` headers are only attached when the request target matches the configured `baseUrl` origin.
- **PKCE, `state` and `nonce`**: The authorization code can only be redeemed by the tab that started sign-in, callbacks that don't match the pending sign-in are rejected, and ID tokens are bound to the request.
- **Automatic Token Refresh & Revocation Handling**: Proactively refreshes expiring access tokens via the provider's token endpoint. If the refresh token has been revoked (logout elsewhere, deleted user), the failed refresh clears local state and emits `SIGNED_OUT`. The OgnaStack gateway checks every access token with the provider, so revoked tokens stop working within seconds.
- **Flexible Storage Strategies**:
  - `storageStrategy: "memory"` keeps tokens strictly in memory to eliminate XSS token exfiltration from `localStorage` or `document.cookie`.
  - `storageStrategy: "sessionStorage"` scopes tokens to the current browser tab.
  - `storageStrategy: "cookie"` automatically applies `SameSite=Lax` and sets `; Secure` when running on HTTPS while allowing local `http://localhost` development.
- **Path Traversal Prevention**: All bucket and file names are validated and URL-encoded before building `/storage/v1/buckets/...` URLs.

---

## Development

```bash
# Lint source files
npm run lint

# Build CJS, ESM, and TypeScript declarations
npm run build

# Run test suite
npm test
```

---

## License

MIT
