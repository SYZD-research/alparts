import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';
import type { User } from '@alparts/shared';
import { api } from './api';
export function canUsePasskeys(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    ['https:', 'http:'].includes(window.location.protocol) &&
    typeof window.PublicKeyCredential !== 'undefined'
  );
}
export interface AuthenticationOptions {
  id: string;
  options: PublicKeyCredentialRequestOptionsJSON;
  passwordAllowed: boolean;
}
export async function loginWithPasskey() {
  const options = await api.securityRequest<AuthenticationOptions>(
    '/auth/passkeys/login/options',
    {},
  );
  const response = await startAuthentication({ optionsJSON: { ...options.options, extensions: {} } });
  response.clientExtensionResults = {};
  return api.securityRequest<{ user: User }>('/auth/passkeys/login/verify', {
    id: options.id,
    response,
  });
}
export async function registerPasskey(name: string) {
  const options = await api.securityRequest<{
    id: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>('/auth/passkeys/register/options', {});
  const response = await startRegistration({ optionsJSON: { ...options.options,
    extensions: { credProps: true, prf: {} } as PublicKeyCredentialCreationOptionsJSON['extensions'],
  } });
  // Never forward secret extension outputs, even if an authenticator provides them.
  response.clientExtensionResults = { credProps: response.clientExtensionResults.credProps };
  await api.securityRequest('/auth/passkeys/register/verify', {
    id: options.id,
    response,
    name,
  });
}
export async function completeStepUp(
  purpose: string,
  options: AuthenticationOptions,
  password: string,
) {
  const proof = options.passwordAllowed
    ? { password }
    : { response: await startAuthentication({ optionsJSON: { ...options.options, extensions: {} } }) };
  if ('response' in proof && proof.response) proof.response.clientExtensionResults = {};
  return api.securityRequest<{ token: string }>('/auth/step-up/verify', {
    id: options.id,
    purpose,
    ...proof,
  });
}
