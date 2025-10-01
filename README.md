# Ogna JS (GoTrue Auth Wrapper)

A lightweight TypeScript wrapper around [Netlify GoTrue](https://github.com/netlify/gotrue) that simplifies authentication and API requests in Ogna FrontEnd apps.

---

## ✨ Features

- 🔑 Login, signup, logout with GoTrue
- 🔄 Automatic JWT refresh
- 💾 Session persistence in `localStorage`
- 🌐 Easy `GET`, `POST`, `PUT`, `DELETE` helpers that attach auth headers
- ⚛️ React Context provider for seamless integration

---

## 📦 Installation

```bash
npm install @your-scope/gotrue-wrapper
# or
yarn add @your-scope/gotrue-wrapper
```

---

## ⚡ Quick Start (React)

### 1. Set up the `AuthProvider`

Wrap your app in the `AuthProvider`, passing the Netlify Identity URL and your API base URL:

```tsx
// AuthProvider.tsx
import React, { createContext, useContext, useMemo } from "react";
import { OgnaClient } from "@your-scope/gotrue-wrapper";

// context holds the client
const AuthContext = createContext<OgnaClient | undefined>(undefined);

export const AuthProvider: React.FC<{
  children: React.ReactNode;
  baseUrl: string;
}> = ({ children, baseUrl }) => {
  // create only once
  const auth = useMemo(() => new OgnaClient(baseUrl), [baseUrl]);

  return <OgnaClient.Provider value={auth}>{children}</OgnaClient.Provider>;
};

// easy hook
export const useAuth = (): OgnaClient => {
  const ctx = useContext(OgnaClient);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
};
```

---

### 2. Use `useAuth` anywhere

```tsx
// Todos.tsx
import React, { useState } from "react";
import { useAuth } from "@your-scope/gotrue-wrapper/react";

export default function Todos() {
  const auth = useAuth(); // full AuthClient instance
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [todos, setTodos] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    try {
      await auth.login(email, password);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const loadTodos = async () => {
    const { data, error } = await auth.get<any[]>("/todos");
    if (error) setError(error.message);
    if (data) setTodos(data);
  };

  if (!auth.getUser()) {
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
      <h2>Welcome {auth.getUser()?.email}</h2>
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

## 📚 API (AuthClient)

```ts
const auth = new AuthClient(identityUrl, apiBaseUrl);

// Authentication
await auth.signup(email, password);
await auth.login(email, password);
await auth.logout();
const user = auth.getUser();

// API calls with auth headers
const { data, error } = await auth.get("/todos");
const { data, error } = await auth.post("/todos", { title: "New task" });
```

Each API call returns `{ data, error }` instead of throwing.

---

## 🛠 Development

```bash
# Build
npm run build

# Run example React app (if you add one in /example)
cd example && npm install && npm start
```

---

## 📄 License

MIT © Your Name
