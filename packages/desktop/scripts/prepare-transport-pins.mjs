import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseTransportPins } from '../dist/transport-pins.js';

const input = process.env.ALPARTS_TRANSPORT_PINS_FILE
  ? resolve(process.env.ALPARTS_TRANSPORT_PINS_FILE) : new URL('../transport-pins.json', import.meta.url);
const config = JSON.parse(await readFile(input, 'utf8'));
parseTransportPins(config, false);
await writeFile(new URL('../dist/transport-pins.json', import.meta.url), JSON.stringify(config) + '\n');
