import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { AxiosError } from "axios"
import { useEffect, useState } from "react"

import { LoginService } from "@/client"
import { AuthLayout } from "@/components/Common/AuthLayout"
import { Button } from "@/components/ui/button"

type CallbackSearch = {
  code?: string
  state?: string
  error?: string
  error_description?: string
}

const exchanges = new Map<string, Promise<string>>()

function exchangeCode(code: string, state: string): Promise<string> {
  const key = `${state}:${code}`
  const existing = exchanges.get(key)
  if (existing) {
    return existing
  }
  const promise = LoginService.oauthCallback({
    body: { code, state },
    withCredentials: true,
  }).then((response) => response.data.access_token)
  exchanges.set(key, promise)
  return promise
}

function callbackErrorMessage(error: unknown): string {
  if (error instanceof AxiosError) {
    const detail = (error.response?.data as { detail?: unknown } | undefined)
      ?.detail
    if (typeof detail === "string") {
      return detail
    }
  }
  return "Sign-in failed. Please try again."
}

export const Route = createFileRoute("/oauth/callback")({
  component: OAuthCallback,
  validateSearch: (search: Record<string, unknown>): CallbackSearch => ({
    code: typeof search.code === "string" ? search.code : undefined,
    state: typeof search.state === "string" ? search.state : undefined,
    error: typeof search.error === "string" ? search.error : undefined,
    error_description:
      typeof search.error_description === "string"
        ? search.error_description
        : undefined,
  }),
  head: () => ({
    meta: [
      {
        title: "Signing in - FastAPI Template",
      },
    ],
  }),
})

function OAuthCallback() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const queryClient = useQueryClient()
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    if (search.error) {
      setMessage(
        search.error_description ||
          "Sign-in was cancelled or rejected by the provider.",
      )
      return
    }
    if (!search.code || !search.state) {
      setMessage("The sign-in response was incomplete. Please try again.")
      return
    }
    let cancelled = false
    exchangeCode(search.code, search.state)
      .then(async (accessToken) => {
        localStorage.setItem("access_token", accessToken)
        await queryClient.invalidateQueries({ queryKey: ["currentUser"] })
        if (!cancelled) {
          await navigate({ to: "/" })
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setMessage(callbackErrorMessage(error))
        }
      })
    return () => {
      cancelled = true
    }
  }, [
    navigate,
    queryClient,
    search.code,
    search.error,
    search.error_description,
    search.state,
  ])

  return (
    <AuthLayout>
      <div className="flex flex-col items-center gap-4 text-center">
        <h1 className="text-2xl font-bold">
          {message ? "Sign-in failed" : "Signing in"}
        </h1>
        <p className="text-muted-foreground text-sm">
          {message ?? "Finishing sign-in with your identity provider."}
        </p>
        {message && (
          <Button asChild>
            <Link to="/login">Back to login</Link>
          </Button>
        )}
      </div>
    </AuthLayout>
  )
}
