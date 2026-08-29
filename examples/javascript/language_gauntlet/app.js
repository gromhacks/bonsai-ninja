// Conventional launcher kept at the project root; the real entry point lives
// under cli/ so module resolution crosses a directory boundary immediately.
module.exports = require("./cli/app");
