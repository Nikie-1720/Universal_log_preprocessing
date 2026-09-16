# ULPF Plugin Contract

A ULPF-certified plugin is a versioned package that declares its identity, supported
format and mapping assets and includes test fixtures.

Minimum contract:

```text
manifest.yaml
parser.py
mappings.yaml
tests/
  sample.log
  expected.json
```

Required parser methods:

```python
detect(event)
parse(event)
normalize(fields)
validate(event)
metadata()
```

The contract is deliberately separate from the ULPF core. A vendor can publish a
plugin without changing the core processing engine. For the hackathon, the live
registry loads the equivalent configuration-driven parser definitions from
`configs/parsers/`.
