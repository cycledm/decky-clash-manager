import deckyPlugin from "@decky/rollup";
import ts from "typescript";

const config = deckyPlugin({});
// Type checking runs through tsc. Transpilation here does not leave the
// template's TypeScript file watchers open after a one-shot build.
config.plugins = config.plugins.map((plugin) => plugin.name === "typescript" ? {
  name: "clash-manager-typescript",
  transform(source, id) {
    if (!/\.tsx?$/.test(id) || id.includes("/node_modules/")) return null;
    const result = ts.transpileModule(source, {
      fileName: id,
      compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext,
        jsx: ts.JsxEmit.ReactJSX, sourceMap: true },
    });
    return { code: result.outputText, map: result.sourceMapText };
  },
} : plugin);

export default config;
