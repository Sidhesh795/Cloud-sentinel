import { expect, test } from "@playwright/test";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

test.use({ channel: process.env.PLAYWRIGHT_CHANNEL || "chromium" });

let server, origin;
test.beforeAll(async () => {
  server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://localhost").pathname;
    if (path !== "/" && !/^\/assets\/[\w.-]+$/.test(path)) return res.writeHead(404).end();
    const file = new URL("../dist" + (path === "/" ? "/index.html" : path), import.meta.url);
    try {
      const body = await readFile(file);
      res.setHeader("Content-Type", path.endsWith(".js") ? "text/javascript" : path.endsWith(".css") ? "text/css" : "text/html");
      res.end(body);
    } catch { res.writeHead(404).end("Run npm run build before this test."); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

async function openConsole(page, role) {
  const user = { id: 7, username: "taylor", role, is_active: true, status: "ACTIVE" };
  const application = { id: 1, organization_id: 1, name: "Payroll", upstream_host: null };
  const requests = [];
  await page.addInitScript(() => localStorage.setItem("cloudsentinel_token", "test-session"));
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname.replace("/api/", "");
    requests.push(path);
    const body = route.request().postDataJSON();
    const responses = {
      health: { demo_mode: false }, "auth/me": user, users: [user], applications: [application],
      "users/7": user, "users/7/posture": {}, "intelligence/users/7/baseline": { samples: 2, required: 10, ready: false, features: {} },
      "intelligence/users/7/snapshots": [{ id: 22, timestamp: "2026-01-01T12:00:00Z", explanations: ["Unusual login hour"] }]
    };
    if (path === "organization") return route.fulfill({ status: 404, json: { detail: "Organization not found" } });
    if (path === "agent/enrollment-tokens") {
      expect(body).toEqual({ user_id: 7, ttl_minutes: 60 });
      return route.fulfill({ status: 201, json: { token: "sample-single-use", user_id: 7, expires_at: "2026-12-01T00:00:00Z" } });
    }
    if (path === "enforce/applications/1/host") {
      application.upstream_host = body.upstream_host;
      return route.fulfill({ status: 204 });
    }
    if (path === "intelligence/snapshots/22/feedback") {
      expect(body.verdict).toBe("FALSE_POSITIVE");
      return route.fulfill({ status: 204 });
    }
    return route.fulfill({ json: responses[path] ?? [] });
  });
  await page.goto(origin);
  await expect(page.getByRole("heading", { name: "No telemetry yet" })).toBeVisible();
  return requests;
}

test("employee can open self-service views before telemetry arrives", async ({ page }) => {
  const requests = await openConsole(page, "employee");
  await expect(page.getByText("Organization: Organization unavailable")).toBeVisible();
  for (const name of ["Agent Enrollment", "Host Mapping", "Behavior Review"])
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  await page.getByRole("button", { name: "Users", exact: true }).click();
  await expect(page.getByText("taylor")).toBeVisible();
  await expect(page.getByTitle("Edit user")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Add User" })).toHaveCount(0);
  expect(requests.filter(path => /^(admin|agent|enforce|intelligence|simulation)\//.test(path))).toEqual([]);
});

test("analyst issues a token, maps and clears a host, and reviews a flagged snapshot", async ({ page }) => {
  await openConsole(page, "SECURITY_ANALYST");
  await page.getByRole("button", { name: "Agent Enrollment" }).click();
  await page.getByRole("button", { name: "Issue enrollment token" }).click();
  await expect(page.getByLabel("Single-use enrollment token")).toHaveValue("sample-single-use");
  await page.getByRole("button", { name: "Host Mapping" }).click();
  await page.getByLabel("Payroll").fill("Payroll.Example.com");
  await page.getByRole("button", { name: "Save host" }).click();
  await expect(page.getByLabel("Payroll")).toHaveValue("payroll.example.com");
  await page.getByLabel("Payroll").fill("");
  await page.getByRole("button", { name: "Remove mapping" }).click();
  await expect(page.getByRole("button", { name: "Remove mapping" })).toBeDisabled();
  await page.getByRole("button", { name: "Behavior Review" }).click();
  await expect(page.getByText("Collecting samples", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Mark false positive" }).click();
  await expect(page.getByRole("status")).toContainText("FALSE POSITIVE");
});
