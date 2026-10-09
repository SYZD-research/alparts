// Runs the real id-form checks (packages/server/src/security/canonical-id.ts)
// on generated inputs. Input: { paths: string[], ids: string[] }.
// Output: { paths: boolean[] (rejected), ids: boolean[] (accepted by canonicalUuid) }.
import { readFileSync } from 'node:fs';

const { hasNonCanonicalUuid, canonicalUuid } = await import('../../packages/server/src/security/canonical-id.ts');
const input = JSON.parse(readFileSync(0, 'utf8')) as { paths: string[]; ids: string[] };
process.stdout.write(JSON.stringify({
  paths: input.paths.map((path) => hasNonCanonicalUuid(path)),
  ids: input.ids.map((id) => canonicalUuid.safeParse(id).success),
}));
