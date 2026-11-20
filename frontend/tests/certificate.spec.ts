import { expect, test } from "@playwright/test"

test.use({ storageState: { cookies: [], origins: [] } })

const user = {
  email: "ada@example.com",
  is_active: true,
  is_superuser: false,
  full_name: "Ada Lovelace",
  id: "00000000-0000-0000-0000-000000000001",
  has_password: true,
}

async function mockProviders(page: import("@playwright/test").Page) {
  await page.route("**/api/v1/login/oauth/providers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data: [] }),
    })
  })
}

test("Sign in with certificate stays hidden when it is disabled", async ({
  page,
}) => {
  await mockProviders(page)
  await page.route("**/api/v1/login/certificate", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ enabled: false }),
    })
  })

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto("/login")

  await expect(page.getByRole("button", { name: "Log In" })).toBeVisible()
  await expect(page.getByTestId("certificate-login")).toHaveCount(0)
})

test("Sign in with certificate stores the access token", async ({ page }) => {
  await mockProviders(page)
  await page.route("**/api/v1/login/certificate", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ enabled: true }),
      })
      return
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        access_token: "cert-test-token",
        token_type: "bearer",
      }),
    })
  })
  await page.route("**/api/v1/users/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(user),
    })
  })

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto("/login")

  const button = page.getByTestId("certificate-login")
  await expect(button).toBeVisible()
  await expect(button).toHaveText("Sign in with certificate")
  const box = await button.boundingBox()
  expect(box?.width ?? 0).toBeGreaterThan(0)
  expect(box?.x ?? 0).toBeGreaterThanOrEqual(0)
  expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(390)

  await button.click()
  await page.waitForURL("/")
  await expect(page.getByText("Welcome back")).toBeVisible()
  const token = await page.evaluate(() => localStorage.getItem("access_token"))
  expect(token).toBe("cert-test-token")
})

test("Settings lists, links, and unlinks a certificate", async ({ page }) => {
  const fingerprint = "ab".repeat(32)
  const certificates = [
    {
      id: "cert-1",
      fingerprint,
      email: "ada@example.com",
      provider: "client-ca",
      created_at: "2026-01-02T00:00:00Z",
    },
  ]

  await page.addInitScript(() => {
    localStorage.setItem("access_token", "settings-token")
  })
  await page.route("**/api/v1/login/certificate", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ enabled: true }),
    })
  })
  await page.route("**/api/v1/users/me/certificates**", async (route) => {
    const method = route.request().method()
    if (method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          data: certificates,
          count: certificates.length,
        }),
      })
      return
    }
    if (method === "DELETE") {
      certificates.splice(0, certificates.length)
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ message: "Certificate unlinked" }),
      })
      return
    }
    const body = route.request().postDataJSON() as { pem?: string }
    certificates.push({
      id: "cert-2",
      fingerprint: "cd".repeat(32),
      email: "ada@example.com",
      provider: "client-ca",
      created_at: "2026-01-03T00:00:00Z",
    })
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "cert-2",
        fingerprint: "cd".repeat(32),
        email: "ada@example.com",
        provider: "client-ca",
        created_at: "2026-01-03T00:00:00Z",
        pem: body.pem,
      }),
    })
  })
  await page.route("**/api/v1/users/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(user),
    })
  })

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto("/settings")
  await page.getByRole("tab", { name: "Certificates" }).click()

  await expect(page.getByText(fingerprint)).toBeVisible()
  const unlink = page.getByTestId("unlink-cert-1")
  const unlinkBox = await unlink.boundingBox()
  expect((unlinkBox?.x ?? 0) + (unlinkBox?.width ?? 0)).toBeLessThanOrEqual(390)
  await unlink.click()
  await expect(page.getByText("Certificate unlinked")).toBeVisible()
  await expect(page.getByTestId("no-certificates")).toBeVisible()

  await page
    .getByTestId("certificate-pem")
    .fill("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
  await page.getByTestId("link-certificate").click()
  await expect(page.getByText("Certificate linked")).toBeVisible()
  await expect(page.getByText("cd".repeat(32))).toBeVisible()
})
