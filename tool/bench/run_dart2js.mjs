import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [artifact] = process.argv.slice(2);
if (artifact === undefined) {
  throw new Error('usage: node tool/bench/run_dart2js.mjs <compiled.js>');
}

globalThis.self = globalThis;
await import(pathToFileURL(resolve(artifact)).href);
