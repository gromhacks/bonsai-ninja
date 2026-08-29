// Cross-directory CommonJS facade. The renamed import in pipeline.js resolves
// here, then the explicit wrapper forwards into the repository implementation.
const { persist: persistRepository } = require("../domain/repository");

async function persist(data) {
  return persistRepository(data);
}

module.exports = { persist };
