import { expect, type Page, test } from "@playwright/test"

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement
    return root.scrollWidth - root.clientWidth
  })
  expect(overflow).toBeLessThanOrEqual(1)
}

test.describe("mobile auth pages", () => {
  test.use({
    viewport: { width: 360, height: 800 },
    storageState: { cookies: [], origins: [] },
  })

  test("login page fits a phone without horizontal scrolling", async ({
    page,
  }) => {
    await page.goto("/login")

    await expect(
      page.getByRole("heading", { name: "Login to your account" }),
    ).toBeVisible()
    await expect(page.getByTestId("email-input")).toBeVisible()
    await expect(page.getByTestId("password-input")).toBeVisible()
    await expect(page.getByRole("button", { name: "Log In" })).toBeVisible()
    await expect(
      page.getByRole("link", { name: "Forgot your password?" }),
    ).toBeVisible()
    await expect(page.getByRole("link", { name: "Sign up" })).toBeVisible()

    await expectNoHorizontalOverflow(page)
  })

  test("signup page fits a phone without horizontal scrolling", async ({
    page,
  }) => {
    await page.goto("/signup")

    await expect(
      page.getByRole("heading", { name: "Create an account" }),
    ).toBeVisible()
    await expect(page.getByRole("button", { name: "Sign Up" })).toBeVisible()

    await expectNoHorizontalOverflow(page)
  })
})

test.describe("mobile dashboard and items", () => {
  test.use({ viewport: { width: 360, height: 800 } })

  test("navigation collapses and items stay on screen", async ({ page }) => {
    await page.goto("/")

    await expect(
      page.getByText("Welcome back, nice to see you again!"),
    ).toBeVisible()
    await expectNoHorizontalOverflow(page)

    const menuButton = page.getByRole("button", { name: /menu|sidebar/i })
    await expect(menuButton).toBeVisible()
    await menuButton.click()

    const itemsLink = page.getByRole("link", { name: "Items" })
    await expect(itemsLink).toBeVisible()
    await itemsLink.click()

    await expect(page.getByRole("heading", { name: "Items" })).toBeVisible()
    await expect(page.getByRole("button", { name: "Add Item" })).toBeVisible()
    await expectNoHorizontalOverflow(page)

    await page.getByRole("button", { name: "Add Item" }).click()
    const dialog = page.getByRole("dialog")
    await expect(dialog).toBeVisible()
    await expect(page.getByRole("heading", { name: "Add Item" })).toBeVisible()

    const box = await dialog.boundingBox()
    const viewport = page.viewportSize()
    expect(box).not.toBeNull()
    expect(viewport).not.toBeNull()
    if (box && viewport) {
      expect(box.x).toBeGreaterThanOrEqual(-1)
      expect(box.y).toBeGreaterThanOrEqual(-1)
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1)
      expect(box.y + box.height).toBeLessThanOrEqual(viewport.height + 1)
    }
  })
})
