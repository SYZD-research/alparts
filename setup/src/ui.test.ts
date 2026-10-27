import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { alignRows, displayWidth, Ui } from './ui.ts';

test('wide characters count as two columns so Japanese labels line up', () => {
  assert.equal(displayWidth('abc'), 3);
  assert.equal(displayWidth('アドレス'), 8);
  assert.equal(displayWidth('Web の公開'), 10);
  assert.deepEqual(alignRows([['アドレス', 'x'], ['Web の公開', 'y']]), ['アドレス    x', 'Web の公開  y']);
});

function streams(lines: string[]) {
  const input = new PassThrough();
  const output = new PassThrough();
  let written = '';
  output.on('data', (chunk: Buffer) => { written += chunk.toString(); });
  for (const line of lines) input.write(`${line}\n`);
  return { input, output, written: () => written };
}

test('questions repeat until the answer is valid, and fall back to the default', async () => {
  const io = streams(['', 'not-a-port', '70000', '587']);
  const ui = new Ui({ input: io.input, output: io.output }, { interactive: true });
  try {
    assert.equal(await ui.ask('Host', { default: 'smtp.example.com' }), 'smtp.example.com');
    const port = await ui.ask('Port', { validate: (answer) => (/^\d+$/.test(answer) && Number(answer) < 65536 ? null : 'bad port') });
    assert.equal(port, '587');
    assert.equal(io.written().split('bad port').length - 1, 2);
  } finally {
    ui.close();
  }
});

test('confirmations and choices accept the usual answers', async () => {
  const io = streams(['', 'n', 'maybe', 'y', '2']);
  const ui = new Ui({ input: io.input, output: io.output }, { interactive: true });
  try {
    assert.equal(await ui.confirm('Go?', true, 'y or n'), true);
    assert.equal(await ui.confirm('Go?', true, 'y or n'), false);
    assert.equal(await ui.confirm('Go?', false, 'y or n'), true);
    assert.equal(await ui.choose('Which?', [{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }], 0, 'pick one'), 'b');
  } finally {
    ui.close();
  }
});

test('without a terminal a question is an error rather than a hang', async () => {
  const io = streams([]);
  const ui = new Ui({ input: io.input, output: io.output });
  await assert.rejects(ui.ask('Domain'));
  ui.close();
});
