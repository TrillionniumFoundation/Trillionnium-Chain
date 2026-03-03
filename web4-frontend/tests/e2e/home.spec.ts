import { expect, test } from "@playwright/test";

test("home page shows readonly chain status", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Trillionnium Web4 Frontend" })).toBeVisible();
  await expect(page.getByText("Chain Status (Read-only)")).toBeVisible();
  await expect(page.getByText("Network: Trillionnium Localnet")).toBeVisible();
});
