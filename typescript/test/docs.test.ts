/**
 * The documentation is checked, not just written.
 *
 * Every published example here is code a consumer will paste. Nothing else in this repository reads
 * it, so an example can name a field that does not exist, or lose an interpolation to a careless
 * edit, and stay wrong indefinitely — the tests all pass, because the tests never look at the
 * README. Both of those have already happened.
 *
 * Two checks, because they catch different things:
 *
 *  * **Type checking** catches drift between an example and the API it demonstrates — a renamed
 *    field, a changed option, a method that no longer exists.
 *  * **The template-literal lint** catches an example that is still valid TypeScript but no longer
 *    says anything: a backtick string with its `${...}` gone prints a sentence with a hole in it,
 *    and no compiler will ever complain.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

/**
 * The package root and the repository root, found by walking up.
 *
 * This file runs from `dist-test/test/` after compilation and from `test/` in an editor, so a fixed
 * number of `..` segments is wrong in one of the two. Walking up to the directory that holds both
 * language packages is right in both.
 */
function roots(): { pkg: string; repo: string } {
  let at = dirname(fileURLToPath(import.meta.url));
  for (let up = 0; up < 8; up += 1) {
    if (existsSync(join(at, 'typescript', 'package.json')) && existsSync(join(at, 'rust'))) {
      return { pkg: join(at, 'typescript'), repo: at };
    }
    at = dirname(at);
  }
  throw new Error('could not locate the repository root from this test file');
}

const { pkg, repo } = roots();

/** The markdown a consumer of this package actually reads. */
const DOCUMENTS = ['README.md', 'SETUP.md', 'typescript/README.md', 'rust/README.md'];

interface Block {
  document: string;
  /** 1-based line of the opening fence, so a failure points at the source. */
  line: number;
  language: string;
  code: string;
}

/** Every fenced code block in `document`. */
function blocks(document: string): Block[] {
  const text = readFileSync(join(repo, document), 'utf8');
  const lines = text.split('\n');
  const found: Block[] = [];
  let open: { line: number; language: string; body: string[] } | null = null;

  for (const [index, line] of lines.entries()) {
    const fence = /^```(\S*)\s*$/.exec(line);
    if (fence === null) {
      if (open !== null) open.body.push(line);
      continue;
    }
    if (open === null) {
      open = { line: index + 1, language: fence[1] ?? '', body: [] };
    } else {
      found.push({
        document,
        line: open.line,
        language: open.language,
        code: open.body.join('\n'),
      });
      open = null;
    }
  }

  assert.equal(open, null, `${document}: an unclosed code fence`);
  return found;
}

const all = DOCUMENTS.flatMap(blocks);

test('the documents contain the examples this checks', () => {
  // A guard against the extractor silently matching nothing — which would turn every check below
  // into a test that passes by looking at an empty list.
  assert.ok(all.length > 20, `only found ${all.length} code blocks across ${DOCUMENTS.length} documents`);
  const typescript = all.filter((block) => block.language === 'ts');
  assert.ok(typescript.length >= 5, `only found ${typescript.length} TypeScript examples`);
});

test('no example contains a template literal that lost its interpolation', () => {
  // A backtick string with no `${` is a string that did not need to be a template literal. In prose
  // examples it is almost always the fossil of an interpolation that was stripped — which is
  // exactly how `slot ${tx.slot} matched filter ${i}` became `slot  matched filter `.
  const offences: string[] = [];

  for (const block of all) {
    if (block.language !== 'ts' && block.language !== 'js' && block.language !== 'rust') continue;
    // Rust examples use backticks only inside comments and doc links, never as string delimiters.
    if (block.language === 'rust') continue;

    const source = ts.createSourceFile('example.ts', block.code, ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      if (ts.isNoSubstitutionTemplateLiteral(node)) {
        offences.push(
          `${block.document}:${block.line}: \`${node.text}\` is a template literal with no interpolation`,
        );
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  assert.deepEqual(offences, [], `\n${offences.join('\n')}\n`);
});

/**
 * Names an example may use without declaring, standing in for the surrounding program.
 *
 * Examples are fragments by design — showing the connect call and the handling around it, not a
 * runnable file. These are declared as *globals* rather than in the file itself, so that an example
 * which does declare its own `client` shadows this one legally instead of colliding with it. That
 * keeps every example checkable exactly as written, which is the point: an example rewritten to
 * satisfy the checker is no longer the example anyone reads.
 */
const GLOBALS = `
import type { MankaShredsClient as SdkClient, MankaShredsEvent as SdkEvent } from '../src/index.js';
type Sdk = typeof import('../src/index.js');

declare global {
  // The package's own exports. Every document opens by showing the import once; repeating it in
  // each fragment afterwards is noise a reader skips, so the fragments are checked as if it were
  // already in scope. A fragment that does show its own import shadows these, which is legal.
  const MankaShredsClient: Sdk['MankaShredsClient'];
  const Stream: Sdk['Stream'];
  const ErrorCode: Sdk['ErrorCode'];
  const ServerError: Sdk['ServerError'];
  const Transaction: Sdk['Transaction'];
  const FRAME_HEADER_LEN: Sdk['FRAME_HEADER_LEN'];
  const MESSAGE_VERSION_LEGACY: Sdk['MESSAGE_VERSION_LEGACY'];
  const readFrameHeader: Sdk['readFrameHeader'];
  const fingerprintOf: Sdk['fingerprintOf'];

  const host: string;
  const port: number;
  const keyId: string;
  const secret: string;
  const bytes: Buffer;
  const der: Buffer;
  const spec: object;
  const fingerprint: string;
  const options: Parameters<typeof SdkClient.connect>[0];
  const handle: (event: SdkEvent) => void;
  const client: SdkClient;
  const event: SdkEvent;
  const index: number;
}
export {};
`;

test('every TypeScript example type checks against this package', () => {
  const examples = all.filter((block) => block.language === 'ts');
  const globals = join(pkg, '__docs__', 'globals.d.ts');
  const sources = new Map<string, string>([[globals, GLOBALS]]);

  for (const [nth, block] of examples.entries()) {
    // Checked at the top level of a module rather than wrapped in a function, so that an example
    // which opens with its own `import` is legal — which most of them do, because that is what a
    // reader has to type.
    sources.set(join(pkg, '__docs__', `example-${nth}.ts`), `${block.code}\nexport {};\n`);
  }

  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ES2022,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    types: ['node'],
    // Without this the DOM library comes in by default, and it declares a global
    // `var event: Event | undefined` — which quietly captures every `event` in these examples and
    // reports them as the wrong type. This is a Node package; the DOM has no business here.
    lib: ['lib.es2022.d.ts'],
    // An example imports the package by the name a consumer installs it under. Pointing that at
    // the sources is what makes the check meaningful — it is this package's real API, under the
    // name the documentation tells people to use.
    baseUrl: pkg,
    paths: { '@manka-shreds/sdk': ['src/index.ts'] },
  };

  const compilerHost = ts.createCompilerHost(options, true);
  const original = compilerHost.getSourceFile.bind(compilerHost);
  compilerHost.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const injected = sources.get(fileName);
    if (injected !== undefined) {
      return ts.createSourceFile(fileName, injected, languageVersion, true);
    }
    return original(fileName, languageVersion, onError, shouldCreate);
  };
  compilerHost.fileExists = (fileName) => sources.has(fileName) || ts.sys.fileExists(fileName);
  compilerHost.readFile = (fileName) => sources.get(fileName) ?? ts.sys.readFile(fileName);

  const program = ts.createProgram([...sources.keys()], options, compilerHost);
  const failures: string[] = [];

  for (const diagnostic of ts.getPreEmitDiagnostics(program)) {
    const file = diagnostic.file;
    if (file === undefined || !sources.has(file.fileName)) continue;
    const nth = Number(/example-(\d+)\.ts/.exec(file.fileName)?.[1] ?? '-1');
    const block = examples[nth];
    if (block === undefined) continue;
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ');
    failures.push(`${block.document}:${block.line}: ${message}`);
  }

  assert.deepEqual(failures, [], `\n${failures.join('\n')}\n`);
});
