# Export schemas

This directory contains immutable machine-readable contracts for versioned
bonsai-ninja exports.

- `bonsai-native-export-v12.schema.json` — current Draft 2020-12 schema for
  `bonsai-ninja export --format json` documents whose `schema` is
  `bonsai-native-export` and whose `schema_version` is `12`. v12 carries the
  code, not only its coordinates: `files[].source` (full file text, the
  index space of every span), `decls[].start` / `end` byte spans,
  `callgraph[].call_text`, `taint_graph.functions[].end_line`, and
  `taint_graph.propagations[].records[].call_column` / `call_text`, so a
  consumer (a training pipeline, a graph database, another analyzer) can
  reconstruct every call stack with its exact source lines from the document
  alone.
- `bonsai-native-export-v11.schema.json`, `bonsai-native-export-v10.schema.json`,
  `bonsai-native-export-v9.schema.json`, `bonsai-native-export-v8.schema.json`, and
  `bonsai-native-export-v7.schema.json` — immutable historical Draft 2020-12
  schemas for `bonsai-ninja export --format json` documents whose `schema` is
  `bonsai-native-export` and whose `schema_version` is `11`, `10`, `9`, `8`, or
  `7`. v11 removed the per-edge `precision` labels (one compiler precision
  level).

An incompatible wire-format change requires a new schema file and a matching
`schema_version` increment. Do not rewrite an existing version to describe a
different contract. The `export_schema_drift` integration test validates all
supported language fixtures and `--full-propagations` output against the
committed schema.
