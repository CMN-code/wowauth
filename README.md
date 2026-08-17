# wowauth

Wow, this standalone service does OAuth for you.

## Development

```
flox activate
just
```

## Docs

- You can find the relevant files in the /docs folder, starting with the /docs/DESCRIPTION.md file (human-written)
- Examples are in /docs/examples (agent-written)
- The DB schema is partially described in /docs/SCHEMA.md (agent-written)

## Testing

- `just test` runs the Rust unit tests.
- `just integration-test` runs the end-to-end suite in /tests (TypeScript/vitest, against a
  real running instance and a mock upstream OAuth provider -- see /tests/README.md).
