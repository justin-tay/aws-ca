import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

/** Runs a program without blocking the event loop, which an in-process HTTP server needs. */
function run(
  command: string,
  args: string[],
  options: { cwd?: string; shell?: boolean } = {},
): Promise<{ status: number; output: string }> {
  return new Promise((done) => {
    const child = spawn(command, args, { ...options });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.on('close', (code) => done({ status: code ?? -1, output }));
  });
}

/** jscep is a sibling checkout (`../jscep`), built with Maven; the conformance test needs Java. */
export const jscepRoot = resolve(__dirname, '../../../../jscep');
const javaTools = ['java', 'javac'].every((tool) => spawnSync(tool, ['-version']).status === 0);
export const jscepAvailable = javaTools && existsSync(join(jscepRoot, 'target', 'classes', 'org'));

export interface ConformanceResult {
  status: number;
  output: string;
  passes: number;
}

/**
 * Compiles and runs `Conformance.java` against a SCEP URL. `renew` is false for a hierarchy that
 * jscep's Bouncy Castle cannot verify on a current JDK (ECDSA), which skips the re-enrollment step.
 */
export async function runConformance(
  url: string,
  challenge: string,
  options: { renew: boolean },
): Promise<ConformanceResult> {
  const classpath = await run('mvn', ['-o', '-q', 'dependency:build-classpath', '-Dmdep.outputFile=cp.txt'], {
    cwd: jscepRoot,
    shell: true,
  });
  if (classpath.status !== 0) {
    throw new Error(`mvn could not build the jscep classpath:\n${classpath.output}`);
  }
  const separator = process.platform === 'win32' ? ';' : ':';
  const cp = [
    join(jscepRoot, 'target', 'classes'),
    readFileSync(join(jscepRoot, 'cp.txt'), 'utf8').trim(),
  ].join(separator);
  const work = mkdtempSync(join(tmpdir(), 'jscep-'));
  const compiled = await run('javac', ['-cp', cp, '-d', work, resolve(__dirname, 'Conformance.java')]);
  if (compiled.status !== 0) {
    throw new Error(`javac failed:\n${compiled.output}`);
  }
  const result = await run('java', [
    '-cp',
    `${work}${separator}${cp}`,
    'Conformance',
    url,
    challenge,
    options.renew ? 'renew' : 'norenew',
  ]);
  return {
    status: result.status,
    output: result.output,
    passes: result.output.match(/^PASS /gm)?.length ?? 0,
  };
}
