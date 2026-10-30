# Small-footprint spoke profile

One or two SQLite spokes with a warm standby restored from shipped backups.
Promotion is a signed operator action. See [spoke-standby.md](../../docs/spoke-standby.md).

```bash
tenkaictl spoke-standby validate --profile examples/spoke-standby/profile.toml
tenkaictl spoke-standby drill \
  --profile examples/spoke-standby/profile.toml \
  --signing-key "$DRILL_SEED" \
  --out spoke-standby-drill.json
```
