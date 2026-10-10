import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { passkeyRouteError } from './account-errors.js';

describe('passkey and step-up route answers', () => {
  it('answers a passkey sign-in at the session limit as a password sign-in, and other errors as before', () => {
    const answers = ['SESSION_LIMIT_REACHED', 'LAST_PASSKEY', 'DEVICE_APPROVAL_REQUIRED', 'INVALID_CREDENTIALS', 'AUDIT_UNAVAILABLE']
      .map((message) => passkeyRouteError(new Error(message)))
      .map((answer) => answer && [answer.status, answer.body.error]);
    assert.deepEqual(answers, [
      [409, 'SESSION_LIMIT_REACHED'],
      [409, 'LAST_PASSKEY'],
      [403, 'DEVICE_APPROVAL_REQUIRED'],
      [403, 'AUTHENTICATION_FAILED'],
      null,
    ]);
    assert.deepEqual(passkeyRouteError(new Error('SESSION_LIMIT_REACHED'))?.body,
      { error: 'SESSION_LIMIT_REACHED', message: 'Revoke an existing session before signing in again', statusCode: 409 });
  });
});
