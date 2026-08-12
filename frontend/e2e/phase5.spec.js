import { expect, test } from "@playwright/test";

test.use({
  launchOptions: {
    executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
  }
});

test("dashboard supports simulation and reset without browser console errors", async ({ page }) => {
  const errors = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));

  await page.goto("http://127.0.0.1:5173");
  await page.getByLabel("Username").fill("developer01");
  await page.getByLabel("Password").fill("CloudDemo123!");
  await page.getByRole("button", { name: "Enter Control Center" }).click();

  await expect(page.getByText("Resource-Level Enforcement")).toBeVisible({ timeout: 15000 });
  await expect(page.getByText("User Risk Monitor")).toBeVisible();
  await expect(page.getByText("Multi-Cloud Enforcement Layer")).toBeVisible();
  await expect(page.getByText("AWS").first()).toBeVisible();
  await expect(page.getByText("AZURE").first()).toBeVisible();
  await expect(page.getByText("GCP").first()).toBeVisible();

  await page.getByText("Customer Database").first().click();
  await expect(page.getByText("ZERO TRUST DECISION")).toBeVisible();
  await expect(page.getByText("FINAL DECISION")).toBeVisible();
  await page.getByRole("button", { name: "Close decision detail" }).click();

  await page.getByRole("button", { name: "Reset Demo" }).click();
  await expect(page.getByText("SYSTEM PROTECTED")).toBeVisible({ timeout: 15000 });
  await expect(page.getByText("Email").first()).toBeVisible();

  await page.getByRole("button", { name: "Simulate Account Compromise" }).click();
  await expect(page.getByText("New device detected")).toBeVisible({ timeout: 5000 });
  await expect(page.getByText("Critical resources restricted")).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("heading", { name: "THREAT CONTAINED" })).toBeVisible({ timeout: 20000 });
  await expect(page.getByText("Customer Database").first()).toBeVisible();
  await expect(page.getByText("DENY").first()).toBeVisible();

  await page.getByRole("button", { name: "Reset Demo" }).click();
  await expect(page.getByText("Demo reset complete")).toBeVisible({ timeout: 10000 });
  await expect(page.getByText("SYSTEM PROTECTED")).toBeVisible({ timeout: 20000 });

  expect(errors).toEqual([]);
});

for (const viewport of [
  { width: 1280, height: 720 },
  { width: 1440, height: 900 }
]) {
  test(`dashboard fits viewport ${viewport.width}x${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.goto("http://127.0.0.1:5173");
    await page.getByLabel("Username").fill("developer01");
    await page.getByLabel("Password").fill("CloudDemo123!");
    await page.getByRole("button", { name: "Enter Control Center" }).click();
    await expect(page.getByText("Resource-Level Enforcement")).toBeVisible({ timeout: 15000 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    expect(overflow).toBe(false);
  });
}
