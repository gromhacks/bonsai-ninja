// Async pipeline — exercises destructuring / rest, array methods
// (map / filter / reduce / flatMap), closures, generators, switch,
// try / catch / finally, template literals, optional chaining, and
// async iterator (for-await-of).
const { persist: persistEnvelope } = require("./storage");

const dynamicStorage = () => import("./storage");

// Generator — yields every token of the tainted command in order.
function* tokenize(cmd) {
  for (const part of cmd.split(" ")) {
    if (part) yield part;
  }
}

// Async generator — re-emits tokens for for-await-of consumption.
async function* stream_tokens(cmd) {
  for (const tok of tokenize(cmd)) {
    yield tok;
  }
}

// Closure factory — returns a reducer that concatenates via template
// literal while preserving taint.
const make_joiner = (sep) => (acc, tok) => acc ? `${acc}${sep}${tok}` : tok;

async function orchestrate(envelope) {
  const { cmd, user, ...rest } = envelope; // destructuring + rest
  const extraCount = envelope.extras?.length ?? 0;
  if (extraCount < 0) throw new Error("unreachable");

  // Collect tainted tokens via async iteration.
  const tokens = [];
  for await (const tok of stream_tokens(cmd)) {
    tokens.push(tok);
  }

  // Array pipeline: map → filter → flatMap → reduce.
  const joined = tokens
    .map((s) => s.trim())
    .filter(Boolean)
    .flatMap((s) => [s])
    .reduce(make_joiner(" "), "");

  // switch/case — every branch re-binds the tainted string.
  let routed;
  switch (envelope.kind) {
    case "run":
      routed = `${joined}`;
      break;
    case "eval":
      routed = joined.trim();
      break;
    default:
      routed = joined;
  }

  // try/catch/finally — taint survives the try block.
  let valid;
  try {
    if (!routed) throw new Error("empty");
    valid = { ...rest, user, cmd: routed };
  } catch (err) {
    valid = { ...rest, user, cmd: routed ?? "" };
  } finally {
    // no-op — present so the adapter sees the finally clause.
  }

  return await persistEnvelope(valid);
}

module.exports = { orchestrate, tokenize, stream_tokens };
