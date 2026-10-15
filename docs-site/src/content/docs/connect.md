---
title: Connect a service
description: Four ways to get a credential into the broker, in order of preference.
---

The credential travels from the provider to the broker. Not through a hub, not
through us. Three of the four ways below hold to that exactly; the fourth says
plainly where it does not.

```sh
stk add github          # add the service, with safe default policy
stk connect github      # the credential, read from stdin — never a flag
```

A flag would land in shell history and in the process table, so the credential
is read from stdin only.

## 1. Paste it

```sh
pbpaste | stk connect github        # macOS
stk connect github                  # then paste, then ctrl-D
```

For a token you already hold. Nothing is printed back but the number of fields
sealed and where.

## 2. A browser on this machine — OAuth 2.0 with PKCE

```sh
stk connect x --browser
```

The broker opens the provider's authorization page, receives the redirect on
loopback, and exchanges the code. The **refresh token** is stored; the access
token is not — it is acquired on demand, so a stolen store yields something that
must be exchanged with the provider before it is worth anything.

You register your own OAuth app and name its client id in `supertoolkit.yaml`:

```yaml
services:
  x:
    oauth2:
      client_id: <your app's client id>
      # only if the app is already registered with a different loopback callback
      redirect_uri: http://localhost:8080/callback
```

supertoolkit ships no client id. A shared one would make every installation look
like the same app to the provider, and be a single point of revocation for
everyone. A client id is public by OAuth's design — it names an app and
authorises nothing — so it is safe in a committed file. A client secret is not,
and is read from stdin.

The redirect must be loopback: the broker receives it itself, so a callback
anywhere else never arrives, and one reachable from the network would let anyone
on it deliver a code to you.

## 3. No browser on this machine — the device grant

```sh
stk connect github --device
```

The provider issues a short code. You approve it in a browser **anywhere** — a
phone is fine — and the token comes back to the broker directly, without ever
touching the machine you approved from.

```
code  9688-D9DD
open  https://github.com/login/device
enter the code to approve it; it is useless to anyone who does not
```

The **user code** above may be read aloud, screenshotted or sent through a
webhook: it does nothing without the person who approves it. The **device code**
— the value the poll redeems — never appears in any output.

Where the provider issues a refresh token, it is kept, and the connection renews
itself. Where it does not, the command says so rather than leaving you to find
out at the expiry.

Configure notifications so the code reaches you when nobody is watching the
terminal:

```yaml
notify:
  webhook: https://ntfy.sh/your-topic
  file: /var/log/stk-notify.log
```

## 4. Last resort — encrypted hand-over

For a machine with no browser whose provider offers no device grant.

```sh
# on the broker
stk handover key

# on a machine that has a browser, with the credential
stk handover seal github --to '<the key>'

# back on the broker
stk handover open github
```

The broker publishes a key that can only seal. Only its private half opens the
envelope, and a tampered one fails rather than yielding partial material.

**This path costs something the others do not**, and the commands say so: the
credential exists on the sealing machine while it is sealed, and still exists
there afterwards. Prefer the device grant or the web interface whenever either
is possible.

## Withdrawing a credential

```sh
stk revoke github
```

Deleting our copy does not invalidate the token at the provider. Where the
provider offers revocation we call it; where it does not, the output says the
credential may still be valid and gives you the page that can withdraw it. It
never claims more than it did.
