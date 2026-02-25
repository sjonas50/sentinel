import { describe, it, expect, beforeEach } from "vitest";
import { setAuth, getToken, getUser, clearAuth, isAuthenticated } from "./auth";

// Build a minimal test JWT
function fakeToken(sub: string, tenantId: string, role = "analyst"): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({ sub, tenant_id: tenantId, role }));
  return `${header}.${payload}.test-sig`;
}

describe("auth service", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("setAuth stores token and returns user", () => {
    const token = fakeToken("bob", "tid-1", "admin");
    const user = setAuth(token);
    expect(user.sub).toBe("bob");
    expect(user.tenant_id).toBe("tid-1");
    expect(user.role).toBe("admin");
    expect(getToken()).toBe(token);
  });

  it("getUser returns stored user", () => {
    setAuth(fakeToken("carol", "tid-2"));
    const user = getUser();
    expect(user?.sub).toBe("carol");
  });

  it("clearAuth removes credentials", () => {
    setAuth(fakeToken("dave", "tid-3"));
    expect(isAuthenticated()).toBe(true);
    clearAuth();
    expect(isAuthenticated()).toBe(false);
    expect(getToken()).toBeNull();
    expect(getUser()).toBeNull();
  });

  it("isAuthenticated reflects login state", () => {
    expect(isAuthenticated()).toBe(false);
    setAuth(fakeToken("eve", "tid-4"));
    expect(isAuthenticated()).toBe(true);
  });
});
