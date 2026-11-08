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

const ISSUER = "http://auth.localhost:8000";
const CLIENT_ID = "1234@ogna";
const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth/v2/authorize`,
  token_endpoint: `${ISSUER}/oauth/v2/token`,
  userinfo_endpoint: `${ISSUER}/oidc/v1/userinfo`,
  revocation_endpoint: `${ISSUER}/oauth/v2/revoke`,
  end_session_endpoint: `${ISSUER}/oidc/v1/end_session`,
};

function createIdToken(claims) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "RS256", typ: "JWT" })}.${enc({
    iss: ISSUER,
    aud: CLIENT_ID,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...claims,
  })}.signature`;
}

/** Routes fake responses by URL; records every call (with decoded form bodies). */
function mockOidcFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    const form =
      typeof options.body === "string" &&
      String(options.headers?.["Content-Type"]).includes("x-www-form-urlencoded")
        ? Object.fromEntries(new URLSearchParams(options.body))
        : null;
    calls.push({ url, options, form });
    let handler = null;
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      handler = routes.discovery ?? (() => ({ status: 200, body: DISCOVERY }));
    } else {
      for (const [prefix, h] of Object.entries(routes)) {
        if (prefix !== "discovery" && url.startsWith(prefix)) {
          handler = h;
          break;
        }
      }
    }
    const result = handler ? await handler(url, options, form) : { status: 404, body: {} };
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
        get: (name) =>
          name.toLowerCase() === "content-length" ? String(bodyText.length) : null,
      },
      json: async () => JSON.parse(bodyText),
      text: async () => bodyText,
      blob: async () => new Blob([bodyText]),
    };
  };
  return { fetchImpl, calls };
}

function oidcClient(fetchImpl, extra = {}) {
  const navigated = [];
  const client = new OgnaClient("http://localhost:8000", {
    storageStrategy: "memory",
    fetch: fetchImpl,
    auth: {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: "http://localhost:3000/auth/callback",
      postLogoutRedirectUri: "http://localhost:3000/",
      navigate: (url) => navigated.push(url),
      ...extra,
    },
  });
  return { client, navigated };
}

async function signIn(client, navigated, tokenBody) {
  await client.auth.signInWithRedirect({ returnTo: "/protected" });
  const authUrl = new URL(navigated[navigated.length - 1]);
  const state = authUrl.searchParams.get("state");
  const nonce = authUrl.searchParams.get("nonce");
  const result = await client.auth.handleRedirectCallback(
    `http://localhost:3000/auth/callback?code=the-code&state=${state}`
  );
  return { authUrl, state, nonce, result, tokenBody };
}

describe("AuthClient OIDC sign-in (Authorization Code + PKCE)", () => {
  it("redirects with PKCE, exchanges the code, stores the session and attaches the token to API calls", async () => {
    let nonceSeen = null;
    const { fetchImpl, calls } = mockOidcFetch({
      [DISCOVERY.token_endpoint]: () => ({
        status: 200,
        body: {
          access_token: "opaque-access-1",
          refresh_token: "refresh-1",
          id_token: createIdToken({
            sub: "312345678901234567",
            email: "dev@ogna.io",
            name: "Dev",
            nonce: nonceSeen,
            "urn:zitadel:iam:org:project:roles": { editor: {}, admin: {} },
          }),
          token_type: "Bearer",
          expires_in: 3600,
        },
      }),
      "http://localhost:8000/api/": () => ({ status: 200, body: [{ id: 1 }] }),
    });
    const { client, navigated } = oidcClient(fetchImpl);

    const events = [];
    client.auth.onAuthStateChange((event, session) =>
      events.push({ event, email: session?.user?.email ?? null })
    );

    await client.auth.signInWithRedirect({ returnTo: "/protected", loginHint: "dev@ogna.io" });
    const authUrl = new URL(navigated[0]);
    assert.equal(authUrl.origin + authUrl.pathname, DISCOVERY.authorization_endpoint);
    assert.equal(authUrl.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(authUrl.searchParams.get("response_type"), "code");
    assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
    assert.match(authUrl.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
    assert.equal(authUrl.searchParams.get("scope"), "openid profile email offline_access");
    assert.equal(authUrl.searchParams.get("login_hint"), "dev@ogna.io");
    nonceSeen = authUrl.searchParams.get("nonce");

    const callbackUrl = `http://localhost:3000/auth/callback?code=the-code&state=${authUrl.searchParams.get("state")}`;
    assert.equal(client.auth.isRedirectCallback(callbackUrl), true);
    const result = await client.auth.handleRedirectCallback(callbackUrl);
    assert.equal(result.error, null);
    assert.equal(result.data.returnTo, "/protected");

    const tokenCall = calls.find((c) => c.url === DISCOVERY.token_endpoint);
    assert.equal(tokenCall.form.grant_type, "authorization_code");
    assert.equal(tokenCall.form.code, "the-code");
    assert.equal(tokenCall.form.client_id, CLIENT_ID);
    assert.equal(tokenCall.form.redirect_uri, "http://localhost:3000/auth/callback");
    assert.match(tokenCall.form.code_verifier, /^[A-Za-z0-9_-]{43}$/);
    // The verifier hashes to the challenge sent in the authorization request
    const expected = require("node:crypto")
      .createHash("sha256")
      .update(tokenCall.form.code_verifier)
      .digest("base64url");
    assert.equal(authUrl.searchParams.get("code_challenge"), expected);
    assert.equal(tokenCall.options.headers.Authorization, undefined);

    assert.equal(client.auth.isLoggedIn(), true);
    assert.equal(client.user.id, "312345678901234567");
    assert.equal(client.user.email, "dev@ogna.io");
    assert.deepEqual(client.user.roles, ["admin", "editor"]);

    const api = await client.get("/todos", { params: { limit: 10 } });
    assert.deepEqual(api.data, [{ id: 1 }]);
    const apiCall = calls.find((c) => c.url.startsWith("http://localhost:8000/api/"));
    assert.equal(apiCall.url, "http://localhost:8000/api/todos?limit=10");
    assert.equal(apiCall.options.headers.Authorization, "Bearer opaque-access-1");

    assert.deepEqual(events, [
      { event: "INITIAL_SESSION", email: null },
      { event: "SIGNED_IN", email: "dev@ogna.io" },
    ]);
  });

  it("rejects a callback whose state does not match", async () => {
    const { fetchImpl, calls } = mockOidcFetch({});
    const { client, navigated } = oidcClient(fetchImpl);
    await client.auth.signInWithRedirect();
    assert.ok(navigated[0]);
    const result = await client.auth.handleRedirectCallback(
      "http://localhost:3000/auth/callback?code=x&state=forged"
    );
    assert.equal(result.error.error_code, "state_mismatch");
    assert.equal(client.auth.isLoggedIn(), false);
    assert.equal(calls.some((c) => c.url === DISCOVERY.token_endpoint), false);
  });

  it("rejects an ID token with the wrong nonce", async () => {
    const { fetchImpl } = mockOidcFetch({
      [DISCOVERY.token_endpoint]: () => ({
        status: 200,
        body: {
          access_token: "a",
          id_token: createIdToken({ sub: "1", nonce: "not-the-nonce" }),
          expires_in: 3600,
        },
      }),
    });
    const { client, navigated } = oidcClient(fetchImpl);
    const { result } = await signIn(client, navigated);
    assert.equal(result.error.error_code, "nonce_mismatch");
    assert.equal(client.auth.isLoggedIn(), false);
  });

  it("surfaces errors returned by the identity provider", async () => {
    const { fetchImpl } = mockOidcFetch({});
    const { client, navigated } = oidcClient(fetchImpl);
    await client.auth.signInWithRedirect();
    const state = new URL(navigated[0]).searchParams.get("state");
    const result = await client.auth.handleRedirectCallback(
      `http://localhost:3000/auth/callback?error=access_denied&error_description=User+cancelled&state=${state}`
    );
    assert.equal(result.error.error_code, "access_denied");
    assert.equal(result.error.msg, "User cancelled");
  });

  it("uses prompt=create for sign-up", async () => {
    const { fetchImpl } = mockOidcFetch({});
    const { client, navigated } = oidcClient(fetchImpl);
    await client.auth.signUpWithRedirect();
    assert.equal(new URL(navigated[0]).searchParams.get("prompt"), "create");
  });

  it("explains missing configuration", async () => {
    const client = new OgnaClient("http://localhost:8000", { storageStrategy: "memory" });
    await assert.rejects(() => client.auth.signInWithRedirect(), /options\.auth\.issuer/);
  });
});

describe("AuthClient token refresh, retry and logout", () => {
  function sessionFixture(overrides = {}) {
    return {
      access_token: "access-old",
      refresh_token: "refresh-old",
      id_token: createIdToken({ sub: "u1", email: "dev@ogna.io" }),
      expires_in: 3600,
      token_type: "Bearer",
      user: { id: "u1", email: "dev@ogna.io" },
      ...overrides,
    };
  }

  it("proactively refreshes an expired token once for concurrent requests", async () => {
    let refreshCalls = 0;
    const { fetchImpl, calls } = mockOidcFetch({
      [DISCOVERY.token_endpoint]: (url, opts, form) => {
        refreshCalls++;
        assert.equal(form.grant_type, "refresh_token");
        assert.equal(form.refresh_token, "refresh-old");
        assert.equal(form.client_id, CLIENT_ID);
        return { status: 200, body: { access_token: "access-new", expires_in: 3600 } };
      },
      "http://localhost:8000/api/": () => ({ status: 200, body: { ok: true } }),
    });
    const { client } = oidcClient(fetchImpl);
    client.auth.setSession(
      sessionFixture({ expires_at: Math.floor(Date.now() / 1000) - 60 })
    );
    assert.equal(client.auth.isTokenExpired(), true);

    const [r1, r2] = await Promise.all([client.get("/items/1"), client.get("/items/2")]);
    assert.equal(refreshCalls, 1);
    assert.deepEqual(r1.data, { ok: true });
    assert.deepEqual(r2.data, { ok: true });
    assert.equal(client.auth.getToken(), "access-new");
    // Refresh token kept when the provider does not rotate it; user preserved
    assert.equal(client.session.refresh_token, "refresh-old");
    assert.equal(client.user.email, "dev@ogna.io");
    const apiCalls = calls.filter((c) => c.url.startsWith("http://localhost:8000/api/"));
    assert.ok(apiCalls.every((c) => c.options.headers.Authorization === "Bearer access-new"));
  });

  it("retries once on 401 after refreshing", async () => {
    let apiCalls = 0;
    const { fetchImpl, calls } = mockOidcFetch({
      [DISCOVERY.token_endpoint]: () => ({
        status: 200,
        body: { access_token: "access-rotated", refresh_token: "refresh-rotated", expires_in: 3600 },
      }),
      "http://localhost:8000/api/": () =>
        ++apiCalls === 1
          ? { status: 401, body: { message: "Invalid or expired token" } }
          : { status: 200, body: { secret: "data" } },
    });
    const { client } = oidcClient(fetchImpl);
    client.auth.setSession(sessionFixture());

    const result = await client.get("/protected");
    assert.deepEqual(result.data, { secret: "data" });
    const last = calls.filter((c) => c.url.startsWith("http://localhost:8000/api/")).pop();
    assert.equal(last.options.headers.Authorization, "Bearer access-rotated");
    assert.equal(client.session.refresh_token, "refresh-rotated");
  });

  it("signs out when the refresh token is rejected", async () => {
    const { fetchImpl } = mockOidcFetch({
      [DISCOVERY.token_endpoint]: () => ({
        status: 400,
        body: { error: "invalid_grant", error_description: "refresh token invalid" },
      }),
    });
    const { client } = oidcClient(fetchImpl);
    client.auth.setSession(sessionFixture());
    const events = [];
    client.auth.onAuthStateChange((e) => events.push(e));
    const res = await client.auth.refreshSession();
    assert.equal(res.error.error_code, "invalid_grant");
    assert.equal(res.error.msg, "refresh token invalid");
    assert.equal(client.auth.isLoggedIn(), false);
    assert.deepEqual(events, ["INITIAL_SESSION", "SIGNED_OUT"]);
  });

  it("logout revokes both tokens, clears the session and ends the provider session", async () => {
    const { fetchImpl, calls } = mockOidcFetch({
      [DISCOVERY.revocation_endpoint]: () => ({ status: 200, body: "" }),
    });
    const { client, navigated } = oidcClient(fetchImpl);
    const session = sessionFixture();
    client.auth.setSession(session);

    const res = await client.auth.logout();
    assert.equal(res.error, null);
    assert.equal(client.auth.isLoggedIn(), false);

    const revoked = calls
      .filter((c) => c.url === DISCOVERY.revocation_endpoint)
      .map((c) => c.form.token_type_hint + ":" + c.form.token)
      .sort();
    assert.deepEqual(revoked, ["access_token:access-old", "refresh_token:refresh-old"]);

    const endSession = new URL(navigated[0]);
    assert.equal(endSession.origin + endSession.pathname, DISCOVERY.end_session_endpoint);
    assert.equal(endSession.searchParams.get("id_token_hint"), session.id_token);
    assert.equal(endSession.searchParams.get("post_logout_redirect_uri"), "http://localhost:3000/");
    assert.equal(endSession.searchParams.get("client_id"), CLIENT_ID);
  });

  it("logout({ redirect: false }) stays on the page", async () => {
    const { fetchImpl } = mockOidcFetch({
      [DISCOVERY.revocation_endpoint]: () => ({ status: 200, body: "" }),
    });
    const { client, navigated } = oidcClient(fetchImpl);
    client.auth.setSession(sessionFixture());
    await client.auth.logout({ redirect: false });
    assert.equal(navigated.length, 0);
    assert.equal(client.auth.isLoggedIn(), false);
  });

  it("fetchUser reads the userinfo endpoint with the access token", async () => {
    const { fetchImpl, calls } = mockOidcFetch({
      [DISCOVERY.userinfo_endpoint]: () => ({
        status: 200,
        body: { sub: "u1", email: "new@ogna.io", email_verified: true },
      }),
    });
    const { client } = oidcClient(fetchImpl);
    client.auth.setSession(sessionFixture());
    const res = await client.auth.fetchUser();
    assert.equal(res.data.email, "new@ogna.io");
    assert.equal(client.user.email_verified, true);
    const call = calls.find((c) => c.url === DISCOVERY.userinfo_endpoint);
    assert.equal(call.options.headers.Authorization, "Bearer access-old");
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
