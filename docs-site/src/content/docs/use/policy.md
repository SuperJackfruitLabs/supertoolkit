---
title: Policy and profiles
description: One committed file, defaults that fail safe, and profiles that can only narrow.
---

Policy is one file, committed to your repository, holding no secrets.

```yaml
workspace: default
services:
  github:
    capabilities:
      create_issue: approval     # the agent proposes, you decide
  x:
    oauth2:
      client_id: <your app's client id>
profiles:
  reader:                        # a profile narrows; it can never widen
    github: [get_user, list_repos]
```

## Three answers

| Policy | Meaning |
|---|---|
| `agent` | The caller may trigger the effect directly. |
| `approval` | The agent may propose; a human decides. **This is the zero value**, so a missing or misspelled policy fails safe rather than open. |
| `deny` | Unavailable to anyone on this workspace. A floor no profile can lift. |

## Where the defaults come from

The catalogue classifies each capability by what it does to the world, because
reversibility is the distinction that matters:

- a **read** observes and changes nothing → `agent`
- a **write** changes something you could undo → `approval`
- a **destructive** capability cannot be undone → `approval`

A capability nobody has classified is never agent-callable. An unknown effect is
treated as a write, not as a read.

## Profiles

A profile is a named subset handed to one caller:

```sh
stk mcp --profile reader
```

It can only narrow. A profile naming a capability that policy denies does not
widen it, and an unknown profile does not quietly resolve to the default — it is
an error, because silently granting the default set to a caller that asked for
something else is the wrong direction to fail in.

## Checking what a caller can see

```sh
stk doctor
```

reports the profiles declared and, for each, what it exposes.
