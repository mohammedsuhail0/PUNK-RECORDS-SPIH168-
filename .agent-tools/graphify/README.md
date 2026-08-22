# Graphify Context Structure

This project uses a compact, file-first context system so another model can continue immediately.

```text
AGENTS.md                  operating rules and read order
PROJECT_MAP.md             stable code/runtime map
HANDOFF.md                 current state and exact next action
SHIELDSENSE_UPGRADE.md     product target and phased design
.agent-tools/graphify/     this convention marker
```

## Resume prompt
```text
Read AGENTS.md, PROJECT_MAP.md, HANDOFF.md, and SHIELDSENSE_UPGRADE.md.
Continue only the immediate next action in HANDOFF.md. Preserve existing behavior,
never expose secrets, and update HANDOFF.md when the action is verified.
```
