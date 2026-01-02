# Ogna Javascript

A lightweight Typescript library for accesing Ognastack features. 

---

## Features

- Authentication management: Login, signup, logout
- Session persistence in `localStorage`
- Easy `GET`, `POST`, `PUT`, `DELETE` helpers that attach auth headers
- Storage featires to upload and download files


---

## Installation

```bash
npm install @your-scope/gotrue-wrapper
```

---

## Quick Start (React)

### 1. Set up the `AuthProvider`

Wrap your app in the `AuthProvider`, passing the ognastack base URL

```tsx
// AuthProvider.tsx
import React, { createContext, useContext, useMemo } from "react";
import { OgnaClient } from "@your-scope/gotrue-wrapper";

// context holds the client
const OgnaContext = createContext<OgnaClient | undefined>(undefined);

export const useAuth = (): OgnaClient => {
  const ctx = useContext(OgnaContext);
  if (!ctx) {
    throw new Error("OgnaContext must be used within an AuthProvider");
  }
  return ctx;
};

export const OgnaAppContainer = ({ children, baseUrl }: OgnaAppProps) => {
  const auth = useMemo(() => new OgnaClient(baseUrl), [baseUrl]);
  return (
    <OgnaContext.Provider value={auth}>
      {children}
    </OgnaContext.Provider>
  );
};


```

---

### 2. Use `useAuth` anywhere

```tsx
// Todos.tsx
import React, { useState } from "react";
import { useAuth } from "@your-scope/gotrue-wrapper/react";

export default function Todos() {
  const { client } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [todos, setTodos] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    try {
      await client.auth.login(email, password);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const loadTodos = async () => {
    const { data, error } = await client.auth.get<any[]>("/todos");
    if (error) setError(error.message);
    if (data) setTodos(data);
  };

  if (!client.auth.getUser()) {
    return (
      <div>
        <h2>Login</h2>
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="email"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="password"
        />
        <button onClick={handleLogin}>Login</button>
        {error && <p style={{ color: "red" }}>{error}</p>}
      </div>
    );
  }

  return (
    <div>
      <h2>Welcome {client.auth.getUser()?.email}</h2>
      <button onClick={() => auth.logout()}>Logout</button>
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

## Development

```bash
# Build
npm run build

# Run example React app (if you add one in /example)
cd example && npm install && npm start
```

---

## License

MIT
