import { expect, test } from "@playwright/test";

test("home page shows readonly operations dashboard", async ({ page }) => {
  await page.goto("/?mode=mock");

  await expect(page.getByRole("heading", { name: "Operations Dashboard" })).toBeVisible();
  await expect(page.getByText("Trillionnium Chain · Readonly Business Board")).toBeVisible();
  await expect(page.getByText("Data mode: readonly API client", { exact: false })).toBeVisible();

  // Wait until dashboard payload is rendered (post-fetch) instead of asserting during loading state.
  await expect(page.getByRole("heading", { name: "Task Digest" })).toBeVisible();
  await expect(page.getByText("Open execution items:", { exact: false })).toBeVisible();
});
