# @ogna/js — OgnaStack JavaScript & TypeScript SDK

A lightweight, zero-dependency TypeScript/JavaScript SDK for connecting UI applications (React, Next.js, Vite, Vue, Svelte) to [OgnaStack Core](https://github.com/ognastack/core).

---

## Features

- **Zero-Config Setup**: Auto-detects `NEXT_PUBLIC_OGNA_URL`, `VITE_OGNA_URL`, `VITE_API_URL`, `REACT_APP_OGNA_URL`, or `window.location.origin`.
- **Authentication (`client.auth`)**:
  - Login, signup, logout, user profile fetching (`fetchUser`), and reactive `onAuthStateChange` subscriptions.
  - **Automatic JWT Refresh**: Proactively refreshes expired access tokens using `refresh_token` (with concurrent request deduplication) and retries once on `401 Unauthorized`.
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
  storageStrategy: "cookie", // "cookie" | "localStorage" | "sessionStorage" | "memory"
  autoRefreshToken: true,    // Automatically refresh expired JWTs
  timeoutMs: 30000,          // 30s request timeout
});
```

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
  const client = useMemo(() => new OgnaClient(baseUrl), [baseUrl]);
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
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [todos, setTodos] = useState<{ id: string; title: string }[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    const { error } = await client.auth.login(email, password);
    if (error) setError(error.msg);
  };

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
        <h2>Login</h2>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        <button onClick={handleLogin}>Login</button>
        {error && <p style={{ color: "red" }}>{error}</p>}
      </div>
    );
  }

  return (
    <div>
      <h2>Welcome {user?.email}</h2>
      <button onClick={() => client.auth.logout()}>Logout</button>
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
- **Automatic Token Refresh & Blacklist Handling**: Proactively refreshes expiring JWTs via `/auth/token?grant_type=refresh_token`. If a token is revoked (e.g., via OgnaStack's Redis `jwt-blacklist`), a failed refresh automatically clears local state and emits `SIGNED_OUT`.
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
