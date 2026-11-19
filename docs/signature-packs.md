# Community signature packs

The OSS repo supports a deliberately simple pull flow for community-safe signature packs. Packs are versioned JSON manifests that follow the public contract and can be fetched directly from a Git ref or tag.

Example:

```bash
source .venv/bin/activate
driftshield signatures pull community-general --ref <git-tag-or-commit>
```

By default this pulls from `driftshield/driftshield-sdk` and stores the validated manifest under `~/.local/share/driftshield/signatures/<pack-name>/<pack-version>/`.

If you need to test or mirror a pack source, override the source URL directly:

```bash
driftshield signatures pull community-general \
  --ref local-smoke \
  --url http://127.0.0.1:8000/community-general.json
```

Compatibility rules for the current OSS pull path:

- `schema_version` is the compatibility gate and is validated before installation
- `pack_metadata.version` is the pack release version and determines the install path
- only `pack_kind: community` is accepted by the OSS pull path
- the pull flow is intentionally replaceable later without committing DriftShield to a marketplace design
