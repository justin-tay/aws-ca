/* eslint-disable no-console */
/* eslint-disable import/no-extraneous-dependencies */
const esbuild = require('esbuild');
const glob = require('glob');
const path = require('path');

const entryArray = glob.sync('./src/assets/lambda/**/handler.ts');

entryArray.forEach((entryPoint) => {
  const name = path.dirname(
    entryPoint.replace('./src/assets/lambda/handlers/', ''),
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
    target: 'node18',
  });
});
