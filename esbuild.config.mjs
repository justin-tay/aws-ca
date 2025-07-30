import esbuild from 'esbuild';
import { globSync } from 'tinyglobby';
import path from 'path';

const entryArray = globSync('./src/assets/lambda/**/handler.ts');

entryArray.forEach((entryPoint) => {
  console.log(entryPoint);
  const name = path.dirname(
    entryPoint.replace('src/assets/lambda/handlers/', ''),
  );
  const outfile = `dist/assets/lambda/${name}/handler.js`;

  console.info(`Bundling '${entryPoint}' to '${outfile}'`);

  esbuild.build({
    bundle: true,
    entryPoints: [entryPoint],
    mainFields: ['module', 'main'], // Prefer esm to cjs for tree-shaking
    outfile,
    platform: 'node',
    sourcemap: true,
    target: 'node22',
  });
});
