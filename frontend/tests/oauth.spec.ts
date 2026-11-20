import { expect, test } from "@playwright/test"

test.use({ storageState: { cookies: [], origins: [] } })

test("OAuth buttons stay hidden when no providers are enabled", async ({
  page,
}) => {
  await page.route("**/api/v1/login/oauth/providers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data: [] }),
    })
  })

  await page.goto("/login")

  await expect(page.getByRole("button", { name: "Log In" })).toBeVisible()
  await expect(page.getByRole("button", { name: /Continue with/ })).toHaveCount(
    0,
  )
})

test("Login shows a button for each enabled provider", async ({ page }) => {
  await page.route("**/api/v1/login/oauth/providers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: [
          { id: "google", name: "Google" },
          { id: "github", name: "GitHub" },
        ],
      }),
    })
  })

  await page.goto("/login")

  await expect(page.getByTestId("oauth-google")).toHaveText(
    "Continue with Google",
  )
  await expect(page.getByTestId("oauth-github")).toHaveText(
    "Continue with GitHub",
  )
})

test("OAuth callback stores the access token", async ({ page }) => {
  await page.route("**/api/v1/login/oauth/callback", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        access_token: "oauth-test-token",
        token_type: "bearer",
      }),
    })
  })
  await page.route("**/api/v1/users/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        email: "oauth-user@example.com",
        is_active: true,
        is_superuser: false,
        full_name: "OAuth User",
        id: "00000000-0000-0000-0000-000000000001",
        has_password: false,
      }),
    })
  })

  await page.goto("/oauth/callback?code=auth-code&state=auth-state")

  await page.waitForURL("/")
  await expect(page.getByText("Welcome back")).toBeVisible()
  const token = await page.evaluate(() => localStorage.getItem("access_token"))
  expect(token).toBe("oauth-test-token")
})

test("OAuth callback shows a provider error", async ({ page }) => {
  await page.goto(
    "/oauth/callback?error=access_denied&error_description=The+user+cancelled",
  )

  await expect(
    page.locator("p").filter({ hasText: "The user cancelled" }),
  ).toBeVisible()
  await expect(page.getByRole("link", { name: "Back to login" })).toBeVisible()
})
