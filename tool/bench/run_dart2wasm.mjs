import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [artifact] = process.argv.slice(2);
if (artifact === undefined || !artifact.endsWith('.wasm')) {
  throw new Error('usage: node tool/bench/run_dart2wasm.mjs <compiled.wasm>');
}

const wasmPath = resolve(artifact);
const loaderPath = wasmPath.replace(/\.wasm$/, '.mjs');
const { compile } = await import(pathToFileURL(loaderPath).href);
const compiled = await compile(await readFile(wasmPath));
const app = await compiled.instantiate({});
app.invokeMain();
