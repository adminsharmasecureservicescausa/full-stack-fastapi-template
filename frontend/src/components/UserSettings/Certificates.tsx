import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"

import { type ClientCertificatePublic, UsersService } from "@/client"
import { Button } from "@/components/ui/button"
import { LoadingButton } from "@/components/ui/loading-button"
import useCustomToast from "@/hooks/useCustomToast"
import { handleError } from "@/utils"

function formatLinked(value: string | null | undefined) {
  if (!value) return "Linked"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Linked"
  return `Linked ${date.toLocaleDateString()}`
}

const Certificates = () => {
  const queryClient = useQueryClient()
  const { showSuccessToast, showErrorToast } = useCustomToast()
  const [pem, setPem] = useState("")

  const certificates = useQuery({
    queryKey: ["myCertificates"],
    queryFn: async () => (await UsersService.readMyCertificates()).data,
  })

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["myCertificates"] })
  }

  const upload = useMutation({
    mutationFn: (body: string) =>
      UsersService.linkCertificatePem({ body: { pem: body } }),
    onSuccess: () => {
      showSuccessToast("Certificate linked")
      setPem("")
      refresh()
    },
    onError: handleError.bind(showErrorToast),
  })

  const presented = useMutation({
    mutationFn: () => UsersService.linkPresentedCertificate(),
    onSuccess: () => {
      showSuccessToast("Certificate linked")
      refresh()
    },
    onError: handleError.bind(showErrorToast),
  })

  const unlink = useMutation({
    mutationFn: (certificateId: string) =>
      UsersService.unlinkMyCertificate({
        path: { certificate_id: certificateId },
      }),
    onSuccess: () => {
      showSuccessToast("Certificate unlinked")
      refresh()
    },
    onError: handleError.bind(showErrorToast),
  })

  const rows = certificates.data?.data ?? []

  return (
    <div className="flex max-w-xl flex-col gap-6">
      <div>
        <h3 className="py-4 text-lg font-semibold">Client certificates</h3>
        <p className="text-muted-foreground text-sm">
          Link a certificate to sign in with it. Upload the public PEM, or link
          the certificate your browser is presenting to this site.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        {certificates.isLoading && (
          <p className="text-muted-foreground text-sm">Loading certificates…</p>
        )}
        {!certificates.isLoading && rows.length === 0 && (
          <p
            className="text-muted-foreground text-sm"
            data-testid="no-certificates"
          >
            No certificates linked yet.
          </p>
        )}
        {rows.map((certificate: ClientCertificatePublic) => (
          <div
            key={certificate.id}
            className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between"
            data-testid={`certificate-${certificate.fingerprint}`}
          >
            <div className="min-w-0">
              <p className="font-mono text-xs break-all">
                {certificate.fingerprint}
              </p>
              <p className="text-muted-foreground text-sm break-all">
                {[certificate.email, formatLinked(certificate.created_at)]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              className="w-full sm:w-auto"
              data-testid={`unlink-${certificate.id}`}
              disabled={unlink.isPending}
              onClick={() => unlink.mutate(certificate.id)}
            >
              Unlink
            </Button>
          </div>
        ))}
      </div>

      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault()
          const value = pem.trim()
          if (!value || upload.isPending) return
          upload.mutate(value)
        }}
      >
        <label className="text-sm font-medium" htmlFor="certificate-pem">
          Public certificate (PEM)
        </label>
        <textarea
          id="certificate-pem"
          data-testid="certificate-pem"
          value={pem}
          onChange={(event) => setPem(event.target.value)}
          rows={6}
          spellCheck={false}
          placeholder="-----BEGIN CERTIFICATE-----"
          className="border-input bg-transparent placeholder:text-muted-foreground w-full rounded-md border px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
        />
        <input
          type="file"
          accept=".pem,.crt,.cer,application/x-pem-file,application/pkix-cert"
          data-testid="certificate-file"
          className="block w-full text-sm file:mr-3 file:rounded-md file:border file:bg-transparent file:px-3 file:py-2"
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (!file) return
            void file.text().then((text) => setPem(text))
          }}
        />
        <LoadingButton
          type="submit"
          className="w-full sm:w-auto"
          loading={upload.isPending}
          disabled={pem.trim().length === 0}
          data-testid="link-certificate"
        >
          Link certificate
        </LoadingButton>
      </form>

      <div className="flex flex-col gap-2">
        <p className="text-muted-foreground text-sm">
          If your browser already sent a certificate to this site, link that one
          instead of uploading a file.
        </p>
        <LoadingButton
          type="button"
          variant="outline"
          className="w-full whitespace-normal sm:w-auto"
          loading={presented.isPending}
          data-testid="link-presented-certificate"
          onClick={() => presented.mutate()}
        >
          Link the certificate presented to this site
        </LoadingButton>
      </div>
    </div>
  )
}

export default Certificates
