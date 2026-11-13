---
title: Run as a service
description: stk serve, the control socket and who may decide, stk install under systemd, the fixed proxy and stk env, and stk reload.
---

`stk run` starts a broker for one command and stops it afterwards. On a machine
where agents run all the time, run one broker as a daemon instead, and, where an
agent runs as its own OS user, run the broker as another one, so the agent
cannot read the sealed store, its key or the approvals. The agent still reaches
the broker, over a control socket and a loopback proxy.

## `stk serve`

```sh
stk serve
stk serve --proxy-listen 127.0.0.1:8899 --allow-uid 1001 --socket-mode 0660
```

`stk serve` runs the broker and listens on the control socket, `stk.sock` in
the state directory (or `STK_SOCKET`). `stk mcp`, `stk mcp serve`,
`stk approvals` and `stk reload` talk to it when it answers.

| Flag | |
|---|---|
| `--proxy-listen <host:port>` | also keep the egress proxy at this fixed loopback address, key required (below) |
| `--allow-uid <n>` | a uid allowed to call the socket. Repeatable. Without one, the socket's file mode is the only gate |
| `--operator-uid <n>` | a uid allowed to decide approvals. Repeatable. Default: root and the daemon's own uid |
| `--socket-mode 0600\|0660` | the control socket's file mode; `0660` lets the agent's group reach it at all, while `--allow-uid` stays the authorisation |
| `--local-commands-socket <path>` | also serve the proxy on this Unix socket, pinned to the `local-commands` identity ([details](/use/mcp-serve/#the-local-commands-socket)) |
| `--local-commands-mode 0600\|0660` | that socket's file mode |

Each flag also takes `--flag=value`.

### Who may call, and who may decide

The daemon reads each caller's uid from the kernel. With `--allow-uid`, a uid
that is neither an allowed uid nor an operator is refused before any method
runs.

| Control-socket method | Who |
|---|---|
| `approvals.decide` | operator uids only |
| `approvals.list`, `status`, and the four MCP tools | agent and operator uids |
| `reload` | agent and operator uids: it applies the policy file the operator wrote and cannot change it |
| `mcp.spec`, `mcp.decide`, `mcp.visible`, `mcp.done`, `mcp.violation` | agent and operator uids: the [`stk mcp serve`](/use/mcp-serve/) gate, which evaluates policy and records the outcome but never changes policy |

**Only an operator decides.** The socket refuses `approvals.decide` to any uid
that is not an operator. Operator uids are `--operator-uid` (repeatable), or by
default root and the uid the daemon runs as, leaving out either if it is also
an agent uid. A uid named as both an agent and an operator is refused at
startup. The decision records the deciding uid's own account (`name (uid N)`,
from the kernel), never a name the caller sends.

Without `--allow-uid`, `stk serve` warns at every start: any process running as
the daemon's uid, an agent included, is then an operator and can decide its own
approvals. The gate is only as real as the uid split under it.

## `stk install`: its own OS user, under systemd

```sh
sudo stk install --user stk --group stk --agent-uid 1001 [--agent-uid 1002] [--operator-uid 1000] [--unit-name stk]
```

Linux with systemd only; on any other OS it refuses. It must run as root and
needs at least one `--agent-uid`. `--dry-run` prints the plan and the unit and
changes nothing. It creates, if absent:

- a system user (no home, `nologin`) and, with `--group`, that group;
- the state directory (`--state-dir`, default `/var/lib/stk`, `0700`), the
  runtime directory (`--runtime-dir`, default `/run/stk`, `0700`, or `0750`
  with `--group`) and the directory of the policy file (`--config`, default
  `/etc/stk/supertoolkit.yaml`; the directory `0750 root:<group>`);
- `stk-passphrase.key` in the state directory (`0400`, random, never printed),
  which the unit hands to the service with systemd `LoadCredential`, so the
  passphrase is not in an environment file;
- `/etc/systemd/system/<unit-name>.service` (default `stk`), running
  `stk serve --proxy-listen 127.0.0.1:<port> --socket-mode … --allow-uid …`
  with `--proxy-port` (default 8899). Each `--agent-uid` becomes an
  `--allow-uid`, and each `--operator-uid` is passed on.

If a policy file already exists its mode is set to `0640 root:<group>`; install
never creates policy. A second run changes nothing. It refuses to run when the
state directory holds a store but no `stk-passphrase.key`, rather than add a new
passphrase over a store sealed under another key. It does not add agent users
to the group: with `--group`, run `usermod -aG <group> <agent-user>` yourself.
Then `systemctl enable --now <unit-name>`; the report prints the exact command.

On a station installed this way, decide with `sudo stk approvals allow <id>`
(root) or `sudo -u stk stk approvals allow <id>` (the service user), unless
`--operator-uid` named someone else.

### Several instances on one host

To keep one station's agent from ever using another station's brokered
credential, run one stk per station, each with its own user and group,
`--state-dir`, `--runtime-dir`, `--config`, `--proxy-port`, `--agent-uid` and
`--unit-name`:

```sh
sudo stk install --user stk-st2 --group stk-st2 --state-dir /var/lib/stk-st2 \
  --runtime-dir /run/stk-st2 --config /etc/stk-st2/supertoolkit.yaml \
  --proxy-port 8900 --agent-uid 2001 --unit-name stk-st2
```

`--unit-name` takes letters, digits, `_ . -`, at most 64, with no `.service`
suffix and no `@`. Install refuses to overwrite an existing unit of that name
unless its `User=` and state directory are the plan's own. It does not check
that ports or directories are unique across instances: choose them distinct.
Run `stk doctor` and `stk env` with that instance's `STK_HOME`, `STK_CONFIG` and
`STK_SOCKET` (as in its unit) to see that instance only.

## The fixed proxy and `stk env`

`stk serve --proxy-listen <host:port>` (loopback addresses only) publishes the
proxy at a fixed address. It creates `proxy.key` in the state directory
(`0600`), and the broker then answers `407` to any `CONNECT` that does not carry
it, before opening any tunnel. Without `--proxy-listen`, `serve` keeps a random
loopback port and no key.

```sh
stk env          # shell assignments
stk env --json
```

`stk env` prints what a client needs to use that proxy: the proxy URL with the
key as URL userinfo (`HTTPS_PROXY`, `HTTP_PROXY`), the CA path
(`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`), a placeholder for each configured service,
`NODE_USE_ENV_PROXY=1` and `STK_BROKERED=1`. Run it as a user that can read the
state directory.

The proxy key is not a service credential. It gates *use of the broker* and
nothing else: holding it lets a client use the routes policy already allows,
and unlocks no secret. Before printing it, `stk env` checks that the listener
recorded in `proxy.addr` is a live stk proxy, so a stale address left by a
crashed `serve` does not get the key.

`stk run` is unchanged: its per-session loopback proxy is not authenticated
(see [Limitations](/limitations/)).

## `stk reload` and `SIGHUP`

```sh
stk reload
stk reload --json
kill -HUP <pid of stk serve>
```

Both re-read the policy file in the running service. A file that does not load
keeps the old policy and reports why. A service removed from the file stops
being brokered, and its stored credential is kept (`stk revoke` removes a
credential). Policy is read per request, so a tunnel opened before a reload
enforces the new rules on its next request.

## Where stk keeps things

| Variable | |
|---|---|
| `STK_HOME` | the state directory: the CA, the sealed store, the ledger, the approvals queue, the socket. Default: the user configuration directory's `supertoolkit` |
| `STK_CONFIG` | the policy file. Default: `supertoolkit.yaml` in the working directory |
| `STK_SOCKET` | the control socket. Default: `stk.sock` in the state directory |
| `STK_PASSPHRASE` | the store's passphrase, from your init system. Preferred over a keychain or a file beside the ciphertext |
| `STK_PASSPHRASE_FILE` | a file holding the passphrase. A file that is named but unreadable is an error, never a fall back to another key |
| `CREDENTIALS_DIRECTORY` | systemd's; when set and `STK_PASSPHRASE_FILE` is not, the passphrase is read from `stk-passphrase` in it (what `stk install`'s unit uses) |

None of the three passphrase variables is passed on to a child that stk starts.
