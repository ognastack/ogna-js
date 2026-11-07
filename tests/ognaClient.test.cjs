const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  OgnaClient,
  createOgnaClient,
  isAuthError,
} = require("../dist/index.cjs");

function createFakeJwt(expSecondsFromNow) {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: "user-123",
      aud: "authenticated",
      exp: Math.floor(Date.now() / 1000) + expSecondsFromNow,
    })
  ).toString("base64url");
  return `${header}.${payload}.signature`;
}

function mockFetchSequence(handlers) {
  let callIndex = 0;
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, options });
    const handler =
      handlers[Math.min(callIndex, handlers.length - 1)] ||
      (() => ({ status: 200, body: {} }));
    callIndex++;
    const result = await handler(url, options, callIndex - 1);
    const status = result.status ?? 200;
    const bodyText =
      result.body === undefined
        ? ""
        : typeof result.body === "string"
          ? result.body
          : JSON.stringify(result.body);
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: {
        get: (name) => {
          if (name.toLowerCase() === "content-length") {
            return String(bodyText.length);
          }
          return null;
        },
      },
      json: async () => JSON.parse(bodyText),
      text: async () => bodyText,
      blob: async () => new Blob([bodyText]),
    };
  };
  return { fetchImpl, calls };
}

describe("OgnaClient Initialization & Security Validation", () => {
  it("normalizes trailing slashes and supports createOgnaClient helper", () => {
    const client = createOgnaClient("https://api.ogna.dev///", {
      storageStrategy: "memory",
    });
    assert.equal(client.baseUrl, "https://api.ogna.dev");
  });

  it("rejects non-HTTP(S) schemes to prevent URL injection", () => {
    assert.throws(
      () => new OgnaClient("javascript:alert(1)"),
      /Invalid OgnaClient baseUrl/
    );
  });

  it("auto-detects baseUrl from environment variables when omitted", () => {
    process.env.NEXT_PUBLIC_OGNA_URL = "https://env.ogna.dev/";
    try {
      const client = createOgnaClient(undefined, { storageStrategy: "memory" });
      assert.equal(client.baseUrl, "https://env.ogna.dev");
    } finally {
      delete process.env.NEXT_PUBLIC_OGNA_URL;
    }
  });
});

describe("AuthClient Lifecycle, Token Refresh & Events", () => {
  it("logs in, emits SIGNED_IN event, and attaches Bearer token to API calls", async () => {
    const token = createFakeJwt(3600);
    const sessionFixture = {
      access_token: token,
      refresh_token: "refresh-abc",
      expires_in: 3600,
      token_type: "bearer",
      user: {
        id: "u1",
        email: "dev@ogna.io",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
    };

    const { fetchImpl, calls } = mockFetchSequence([
      () => ({ status: 200, body: sessionFixture }),
      () => ({ status: 200, body: [{ id: 1, title: "Ship SDK" }] }),
    ]);

    const client = new OgnaClient("http://localhost:8000", {
      storageStrategy: "memory",
      fetch: fetchImpl,
    });

    const events = [];
    const sub = client.auth.onAuthStateChange((event, session) => {
      events.push({ event, email: session?.user?.email ?? null });
    });

    const loginRes = await client.auth.login("dev@ogna.io", "secret123");
    assert.equal(loginRes.error, null);
    assert.equal(client.auth.isLoggedIn(), true);
    assert.equal(client.user?.email, "dev@ogna.io");

    const todosRes = await client.get("/todos", {
      params: { completed: false, limit: 10 },
    });
    assert.deepEqual(todosRes.data, [{ id: 1, title: "Ship SDK" }]);
    assert.equal(
      calls[1].url,
      "http://localhost:8000/api/todos?completed=false&limit=10"
    );
    assert.equal(calls[1].options.headers.Authorization, `Bearer ${token}`);

    sub.unsubscribe();
    assert.deepEqual(events, [
      { event: "INITIAL_SESSION", email: null },
      { event: "SIGNED_IN", email: "dev@ogna.io" },
    ]);
  });

  it("proactively refreshes expired JWT and deduplicates concurrent refresh requests", async () => {
    const expiredToken = createFakeJwt(-60);
    const freshToken = createFakeJwt(3600);

    let refreshCallCount = 0;
    const { fetchImpl } = mockFetchSequence([
      (url) => {
        if (url.includes("grant_type=refresh_token")) {
          refreshCallCount++;
          return {
            status: 200,
            body: {
              access_token: freshToken,
              refresh_token: "refresh-new",
              expires_in: 3600,
              token_type: "bearer",
              user: {
                id: "u1",
                email: "dev@ogna.io",
                created_at: "",
                updated_at: "",
              },
            },
          };
        }
        return { status: 200, body: { ok: true } };
      },
      () => ({ status: 200, body: { ok: true } }),
      () => ({ status: 200, body: { ok: true } }),
    ]);

    const client = new OgnaClient("http://localhost:8000", {
      storageStrategy: "memory",
      fetch: fetchImpl,
    });

    client.auth.setSession({
      access_token: expiredToken,
      refresh_token: "refresh-old",
      expires_in: 3600,
      expires_at: Math.floor(Date.now() / 1000) - 60,
      token_type: "bearer",
      user: {
        id: "u1",
        email: "dev@ogna.io",
        created_at: "",
        updated_at: "",
      },
    });

    assert.equal(client.auth.isTokenExpired(), true);

    // Fire two concurrent requests while token is expired
    const [res1, res2] = await Promise.all([
      client.get("/items/1"),
      client.get("/items/2"),
    ]);

    assert.equal(refreshCallCount, 1);
    assert.deepEqual(res1.data, { ok: true });
    assert.deepEqual(res2.data, { ok: true });
    assert.equal(client.auth.getToken(), freshToken);
  });

  it("retries once on 401 Unauthorized by refreshing session", async () => {
    const validToken = createFakeJwt(3600);
    const rotatedToken = createFakeJwt(3600);

    const { fetchImpl, calls } = mockFetchSequence([
      // 1st call returns 401 (e.g. blacklisted or expired on server)
      () => ({ status: 401, body: { message: "Token revoked" } }),
      // 2nd call is automatic refreshSession()
      () => ({
        status: 200,
        body: {
          access_token: rotatedToken,
          refresh_token: "refresh-rotated",
          expires_in: 3600,
          token_type: "bearer",
          user: {
            id: "u1",
            email: "dev@ogna.io",
            created_at: "",
            updated_at: "",
          },
        },
      }),
      // 3rd call is automatic retry of original request with new token
      () => ({ status: 200, body: { secret: "data" } }),
    ]);

    const client = new OgnaClient("http://localhost:8000", {
      storageStrategy: "memory",
      fetch: fetchImpl,
    });

    client.auth.setSession({
      access_token: validToken,
      refresh_token: "refresh-initial",
      expires_in: 3600,
      token_type: "bearer",
      user: {
        id: "u1",
        email: "dev@ogna.io",
        created_at: "",
        updated_at: "",
      },
    });

    const result = await client.get("/protected");
    assert.deepEqual(result.data, { secret: "data" });
    assert.equal(calls.length, 3);
    assert.equal(
      calls[2].options.headers.Authorization,
      `Bearer ${rotatedToken}`
    );
  });
});

describe("StorageClient Endpoints & Path Traversal Protection", () => {
  it("prevents path traversal in bucketName and fileName", async () => {
    const { fetchImpl, calls } = mockFetchSequence([]);
    const client = new OgnaClient("http://localhost:8000", {
      storageStrategy: "memory",
      fetch: fetchImpl,
    });

    const badBucket = await client.storage.listFiles("../secrets");
    assert.equal(badBucket.data, null);
    assert.ok(isAuthError(badBucket.error));
    assert.match(badBucket.error.msg, /Invalid bucketName/);

    const badFile = await client.storage.downloadFile(
      "avatars",
      "../../etc/passwd"
    );
    assert.equal(badFile.data, null);
    assert.match(badFile.error.msg, /Invalid fileName/);
    assert.equal(calls.length, 0);
  });

  it("calls aligned /storage/v1/buckets/{bucket}/files endpoints with URL encoding", async () => {
    const { fetchImpl, calls } = mockFetchSequence([
      () => ({ status: 201, body: { accepted: true } }),
      () => ({
        status: 200,
        body: [
          {
            id: "f1",
            bucket_id: "b1",
            name: "my report.pdf",
            last_modified: "2026-01-01T00:00:00Z",
          },
        ],
      }),
      () => ({ status: 200, body: { accepted: true } }),
    ]);

    const client = new OgnaClient("http://localhost:8000", {
      storageStrategy: "memory",
      fetch: fetchImpl,
    });

    await client.storage.createBucket("team-docs", false);
    assert.equal(calls[0].url, "http://localhost:8000/storage/v1/buckets");

    const files = await client.storage.listFiles("team-docs");
    assert.equal(
      calls[1].url,
      "http://localhost:8000/storage/v1/buckets/team-docs/files"
    );
    assert.equal(files.data.length, 1);

    await client.storage.deleteFile("team-docs", "my report.pdf");
    assert.equal(
      calls[2].url,
      "http://localhost:8000/storage/v1/buckets/team-docs/files/my%20report.pdf"
    );
  });
});
