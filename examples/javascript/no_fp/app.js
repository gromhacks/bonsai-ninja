// False-positive audit fixture (JavaScript).
const child_process = require("child_process");

const CONST_OK = "ls /tmp";

function decoy() {
  // NEGATIVE: tainted value bound to an unused local; sink reads CONST_OK.
  const _unused = process.env.IGNORED;
  child_process.exec(CONST_OK);
}

function unrelated_chain() {
  // NEGATIVE: routine code, no source or sink.
  const a = "hello";
  return a.toUpperCase();
}

module.exports = { decoy, unrelated_chain };
