# Export schemas

This directory contains immutable machine-readable contracts for versioned
bonsai-ninja exports.

- `bonsai-native-export-v10.schema.json` — current Draft 2020-12 schema for
  `bonsai-ninja export --format json` documents whose `schema` is
  `bonsai-native-export` and whose `schema_version` is `10`.
- `bonsai-native-export-v9.schema.json`, `bonsai-native-export-v8.schema.json`, and
  `bonsai-native-export-v7.schema.json` — immutable historical Draft 2020-12 schemas for
  `bonsai-ninja export --format json` documents whose `schema` is
  `bonsai-native-export` and whose `schema_version` is `9`, `8`, or `7`.

An incompatible wire-format change requires a new schema file and a matching
`schema_version` increment. Do not rewrite an existing version to describe a
different contract. The `export_schema_drift` integration test validates all
supported language fixtures and `--full-propagations` output against the
committed schema.
