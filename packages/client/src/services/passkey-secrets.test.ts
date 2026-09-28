import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ authentication: vi.fn(), registration: vi.fn(), request: vi.fn() }));
vi.mock('@simplewebauthn/browser', () => ({ startAuthentication: mocks.authentication, startRegistration: mocks.registration }));
vi.mock('./api', () => ({ api: { securityRequest: mocks.request } }));
import { loginWithPasskey, completeStepUp, registerPasskey, type AuthenticationOptions } from './passkey.service';

beforeEach(() => {
  vi.resetAllMocks();
  mocks.authentication.mockResolvedValue({ clientExtensionResults: { prf: { results: { first: 'must-stay-local' } } } });
  mocks.registration.mockResolvedValue({ clientExtensionResults: { credProps: { rk: true }, prf: { results: { first: 'must-stay-local' } } } });
});

describe('passkey secret isolation', () => {
  const options = { id: 'challenge', passwordAllowed: false, options: { challenge: 'test',
    extensions: { prf: { eval: { first: 'server-requested-secret' } } },
  } } as unknown as AuthenticationOptions;
  it('removes server-controlled PRF requests and secret outputs from login and step-up', async () => {
    mocks.request.mockResolvedValue(options);
    await loginWithPasskey();
    await completeStepUp('test-operation', options, '');
    for (const [call] of mocks.authentication.mock.calls) expect(call.optionsJSON.extensions).toEqual({});
    for (const [path, body] of mocks.request.mock.calls) {
      if (path.endsWith('/verify')) expect(body.response.clientExtensionResults).toEqual({});
    }
  });
  it('requests PRF support during registration but sends only public credential properties', async () => {
    mocks.request.mockResolvedValue(options);
    await registerPasskey('My passkey');
    expect(mocks.registration.mock.calls[0][0].optionsJSON.extensions).toEqual({ credProps: true, prf: {} });
    const lastRequest = mocks.request.mock.calls[mocks.request.mock.calls.length - 1];
    expect(lastRequest[1].response.clientExtensionResults).toEqual({ credProps: { rk: true } });
  });
});
