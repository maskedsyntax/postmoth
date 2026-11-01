// Build the extension into dist/. `--dev` pins the development extension
// ID (manifest `key`) and enables localhost test sites.
import * as esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";

const dev = process.argv.includes("--dev");
const root = path.dirname(new URL(import.meta.url).pathname);
const out = path.join(root, "dist");
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out);

const common = {
  bundle: true,
  target: "chrome116",
  minify: !dev,
  sourcemap: false,
  legalComments: "none",
  define: { __DEV__: JSON.stringify(dev) },
  logLevel: "warning",
};
await esbuild.build({ ...common, entryPoints: [path.join(root, "src/background.ts")], outfile: path.join(out, "background.js"), format: "esm" });
for (const name of ["content", "popup"]) {
  await esbuild.build({ ...common, entryPoints: [path.join(root, `src/${name}.ts`)], outfile: path.join(out, `${name}.js`), format: "iife" });
}

const manifest = JSON.parse(fs.readFileSync(path.join(root, "static/manifest.json"), "utf8"));
if (dev) {
  manifest.name += " (dev)";
  manifest.key = fs
    .readFileSync(path.join(root, "../../packaging/native-messaging/dev-extension-key.b64"), "utf8")
    .trim();
  manifest.content_scripts[0].matches.push("http://localhost/*", "https://localhost/*");
}
fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
for (const f of ["popup.html", "popup.css"]) fs.copyFileSync(path.join(root, "static", f), path.join(out, f));
console.log(`built ${dev ? "development" : "release"} extension in ${path.relative(process.cwd(), out) || "."}/`);
