import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { clearDeploymentCookies, type CookieStore } from './session-cookies.js';

const SERVER = 'https://chat.example.test';

// Like the real store, `get` answers only for the cookies of the asked origin.
class FakeCookies implements CookieStore {
  readonly calls: string[] = [];
  constructor(readonly stored: Record<string, string[]>) {}

  async get(filter: { url: string }) {
    this.calls.push(`get ${filter.url}`);
    return (this.stored[filter.url] ?? []).map((name) => ({ name }));
  }

  async remove(url: string, name: string) {
    this.calls.push(`remove ${url} ${name}`);
    this.stored[url] = (this.stored[url] ?? []).filter((candidate) => candidate !== name);
  }

  async flushStore() {
    this.calls.push('flush');
  }
}

describe('desktop sign-out cookies', () => {
  it('removes every cookie of the deployment and writes the removal to disk', async () => {
    const cookies = new FakeCookies({ [SERVER]: ['__Host-alparts_session', 'other'] });
    await clearDeploymentCookies(cookies, [SERVER]);
    assert.deepEqual(cookies.stored[SERVER], []);
    assert.equal(cookies.calls.at(-1), 'flush');
  });

  it('leaves the cookies of other origins alone', async () => {
    const cookies = new FakeCookies({ [SERVER]: ['session'], 'https://elsewhere.example.test': ['session'] });
    await clearDeploymentCookies(cookies, [SERVER]);
    assert.deepEqual(cookies.stored['https://elsewhere.example.test'], ['session']);
  });

  it('clears the development origin as well, and each origin once', async () => {
    const development = 'http://localhost:5173';
    const cookies = new FakeCookies({ [SERVER]: ['session'], [development]: ['session'] });
    await clearDeploymentCookies(cookies, [`${SERVER}/`, development, SERVER]);
    assert.deepEqual(cookies.stored, { [SERVER]: [], [development]: [] });
    assert.equal(cookies.calls.filter((call) => call.startsWith('get ')).length, 2);
  });

  it('does nothing before a server has been chosen', async () => {
    const cookies = new FakeCookies({ [SERVER]: ['session'] });
    await clearDeploymentCookies(cookies, [null, null]);
    assert.deepEqual(cookies.stored[SERVER], ['session']);
  });

  it('refuses an address that is not a deployment origin', async () => {
    const cookies = new FakeCookies({});
    await assert.rejects(clearDeploymentCookies(cookies, ['file:///etc']));
    assert.deepEqual(cookies.calls, []);
  });
});
