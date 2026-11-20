import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ShieldCheck } from "lucide-react"
import { useState } from "react"

import {
  type ClientCertificatePublic,
  type UserPublic,
  UsersService,
} from "@/client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { LoadingButton } from "@/components/ui/loading-button"
import useCustomToast from "@/hooks/useCustomToast"
import { handleError } from "@/utils"

interface UserCertificatesProps {
  user: UserPublic
  onSuccess: () => void
}

const UserCertificates = ({ user, onSuccess }: UserCertificatesProps) => {
  const [isOpen, setIsOpen] = useState(false)
  const queryClient = useQueryClient()
  const { showSuccessToast, showErrorToast } = useCustomToast()

  const certificates = useQuery({
    queryKey: ["userCertificates", user.id],
    queryFn: async () =>
      (await UsersService.readUserCertificates({ path: { user_id: user.id } }))
        .data,
    enabled: isOpen,
  })

  const revoke = useMutation({
    mutationFn: (certificateId: string) =>
      UsersService.revokeUserCertificate({
        path: { user_id: user.id, certificate_id: certificateId },
      }),
    onSuccess: () => {
      showSuccessToast("Certificate revoked")
      queryClient.invalidateQueries({ queryKey: ["userCertificates", user.id] })
      onSuccess()
    },
    onError: handleError.bind(showErrorToast),
  })

  const rows = certificates.data?.data ?? []

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuItem
        onSelect={(event) => event.preventDefault()}
        onClick={() => setIsOpen(true)}
        data-testid={`user-certificates-${user.id}`}
      >
        <ShieldCheck />
        Certificates
      </DropdownMenuItem>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Client certificates</DialogTitle>
          <DialogDescription className="break-all">
            Certificates linked to {user.email}. Revoking one stops sign-in with
            that certificate.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {certificates.isLoading && (
            <p className="text-muted-foreground text-sm">
              Loading certificates…
            </p>
          )}
          {!certificates.isLoading && rows.length === 0 && (
            <p className="text-muted-foreground text-sm">
              No client certificates are linked to this account.
            </p>
          )}
          {rows.map((certificate: ClientCertificatePublic) => (
            <div
              key={certificate.id}
              className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="font-mono text-xs break-all">
                  {certificate.fingerprint}
                </p>
                {certificate.email && (
                  <p className="text-muted-foreground text-sm break-all">
                    {certificate.email}
                  </p>
                )}
              </div>
              <LoadingButton
                type="button"
                variant="destructive"
                className="w-full sm:w-auto"
                loading={revoke.isPending}
                onClick={() => revoke.mutate(certificate.id)}
              >
                Revoke
              </LoadingButton>
            </div>
          ))}
          <Button
            type="button"
            variant="outline"
            className="w-full sm:w-auto"
            onClick={() => setIsOpen(false)}
          >
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default UserCertificates
