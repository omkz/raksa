# Vulnerable SQL Injection Demo

This disposable example intentionally includes vulnerable code for local security education. **Do not expose it to a network or use it with real data.**

Run:

```bash
python -m unittest -v
```

The first test demonstrates the unsafe query returning unintended rows. The second shows the parameterized version treating the same payload as a literal value. The live Raksa UI demo runs the same principle in an in-memory SQLite proof harness without executing untrusted repository code.
