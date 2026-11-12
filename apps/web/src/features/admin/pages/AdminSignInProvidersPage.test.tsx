import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, waitFor } from '@testing-library/react'
import type { EnvironmentView } from '@orbit/api/generated/types.gen'
import { AdminSignInProvidersPage } from './AdminSignInProvidersPage'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

const ENVIRONMENT: EnvironmentView = { registration_open: false, smtp: false, s3: false, attachments_in_s3: false, backups_in_s3: false, backup_schedule: false, s3_keep_deleted_days: false, sign_in_providers: [] }
const GOOGLE = { provider: 'google', client_id: 'google-client', secret_set: true, callback_url: 'https://orbit.example.com/api/v1/auth/providers/google/callback' }

test('a provider set by the environment is read-only, the other stays editable', async () => {
  globalThis.fetch = (async () => Response.json({ registration_open: false, smtp: null, sign_in_providers: [GOOGLE], environment: { ...ENVIRONMENT, sign_in_providers: ['google'] } })) as unknown as typeof fetch
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><AdminSignInProvidersPage /></QueryClientProvider>)

  const google = (await view.findByRole('button', { name: 'Save Google' })) as HTMLButtonElement
  expect(google.disabled).toBe(true)
  expect((view.getByRole('button', { name: 'Remove' }) as HTMLButtonElement).disabled).toBe(true)
  expect((view.getByRole('button', { name: 'Save GitHub' }) as HTMLButtonElement).disabled).toBe(false)
  const clientIds = view.getAllByLabelText(/^Client ID/) as HTMLInputElement[]
  expect(clientIds.map((input) => input.disabled)).toEqual([true, false, false])
  expect(view.getByText('ORBIT_GOOGLE_*')).toBeTruthy()
})

test('the OpenID Connect card sends the label, the issuer and the extra scopes', async () => {
  const requests: { url: string; body: unknown }[] = []
  globalThis.fetch = (async (input: Request | string, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    if (request.method === 'PUT') requests.push({ url: request.url, body: await request.json() })
    return Response.json({ registration_open: false, smtp: null, sign_in_providers: [], environment: ENVIRONMENT })
  }) as unknown as typeof fetch
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><AdminSignInProvidersPage /></QueryClientProvider>)

  const save = await view.findByRole('button', { name: 'Save OpenID Connect' })
  expect((view.getAllByLabelText(/^Callback URL/)[2] as HTMLInputElement).value).toEndWith('/api/v1/auth/providers/oidc/callback')
  fireEvent.change(view.getByLabelText(/^Button label/), { target: { value: ' Authentik ' } })
  fireEvent.change(view.getByLabelText(/^Issuer URL/), { target: { value: 'https://auth.example.com/application/o/orbit/' } })
  fireEvent.change(view.getAllByLabelText(/^Client ID/)[2], { target: { value: 'orbit' } })
  fireEvent.change(view.getAllByLabelText(/^Client secret/)[2], { target: { value: 'not-a-real-secret' } })
  fireEvent.change(view.getByLabelText(/^Extra scopes/), { target: { value: 'groups' } })
  fireEvent.submit(save.closest('form')!)

  await waitFor(() => expect(requests.length).toBe(1))
  expect(requests[0].url).toEndWith('/api/v1/admin/settings/sign-in-providers/oidc')
  expect(requests[0].body).toEqual({ client_id: 'orbit', client_secret: 'not-a-real-secret', display_name: 'Authentik', issuer: 'https://auth.example.com/application/o/orbit/', scopes: 'groups' })
})
