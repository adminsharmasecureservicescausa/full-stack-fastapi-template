import { Appearance } from "@/components/Common/Appearance"
import { Footer } from "./Footer"
import { Logo } from "./Logo"

interface AuthLayoutProps {
  children: React.ReactNode
}

export function AuthLayout({ children }: AuthLayoutProps) {
  return (
    <div className="grid min-h-svh lg:grid-cols-2">
      <div className="bg-muted dark:bg-zinc-900 relative hidden lg:flex lg:items-center lg:justify-center">
        <Logo variant="full" className="h-16" asLink={false} />
      </div>
      <div className="flex min-w-0 flex-col gap-4 p-4 sm:p-6 md:p-10">
        <div className="flex items-center justify-between gap-4">
          <Logo variant="full" className="h-6 lg:hidden" />
          <div className="ml-auto">
            <Appearance />
          </div>
        </div>
        <div className="flex flex-1 items-center justify-center">
          <div className="w-full min-w-0 max-w-sm">{children}</div>
        </div>
        <Footer />
      </div>
    </div>
  )
}
