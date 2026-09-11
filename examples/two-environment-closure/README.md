# Two-environment immutable closure drill

Synthetic software fixture that promotes one signed multi-resource change-set
pin through two isolated environments without republishing member definitions.

See [change-set closure pins](../../docs/change-set-pin.md#two-environment-drill)
and issue [#360](https://github.com/Sannrox/tenkai/issues/360).

```bash
cargo test --locked --test two_environment_closure_drill -- --nocapture
```

The drill uses disposable local state and `tenkaictl dev` keys. It does not
start a cluster or a live change-set service. Rollback restores the recorded
Tenkai pin; it does not undo foreign member documents.
