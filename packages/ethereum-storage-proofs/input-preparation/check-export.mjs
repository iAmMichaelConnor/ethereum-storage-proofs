import { readFileSync } from "node:fs";
import { checkRecursiveProofExport } from "./export.mjs";
checkRecursiveProofExport(JSON.parse(readFileSync(process.argv[2], "utf8")));
console.log(
  "Valid v1 export structure. Proof verification and root/key policy are separate checks.",
);
