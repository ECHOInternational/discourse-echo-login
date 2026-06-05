# ECHO Login

**Single sign-on for Discourse via the main ECHOcommunity site's session.** Users signed in at
[echocommunity.org](https://www.echocommunity.org) are automatically signed in to the forum at
`conversations.echocommunity.org` — no separate login, no SSO round-trip.

> **Part of the [ECHOcommunity Discourse setup](https://github.com/ECHOInternational/discourse-infrastructure)** — the self-hosted Discourse at `conversations.echocommunity.org`.
> Family: [infrastructure](https://github.com/ECHOInternational/discourse-infrastructure) · **echo-login** · [echo-locale](https://github.com/ECHOInternational/discourse-echo-locale) · [echo-nav](https://github.com/ECHOInternational/discourse-echo-nav) · [ECHOcommunity (main site)](https://github.com/ECHOInternational/ECHOcommunity)

## Overview
The main ECHOcommunity site (a Rails app) and the forum share a login cookie on `.echocommunity.org`.
This plugin teaches Discourse to authenticate from that shared session instead of its own login —
so the two sites feel like one. ECHOcommunity staff (`role == "ECHOstaff"`) are provisioned as
Discourse admins/moderators automatically.

## How it works
Replaces Discourse's current-user provider
(`Discourse.current_user_provider = ECHOcommunityCurrentUserProvider < Auth::CurrentUserProvider`).
On each request it:
1. Reads the opaque token from the shared cookie (`TOKEN_COOKIE`, default `_ECHOcommunity_shared_session`).
2. Looks the Rack session up in the shared Redis/ElastiCache, trying the Rack‑2 private‑id key first:
   `SESSION_NAMESPACE:2::<sha256(token)>` → `…:<sha256(token)>` → legacy `…:<token>`.
3. `Marshal.load`s the session and reads the `warden.user.user.*` fields the main site stores
   (email, names, nickname, role, uid, …).
4. Provisions/logs in the user through `DiscourseConnect#lookup_or_create_user`
   (`external_id` = ECHOcommunity uid; `ECHOstaff` ⇒ admin + moderator).

Also supports an `X-Shared-Session-Key` header bypass and an admin impersonation cookie.

## Configuration (env, set in the container config)
| Var | Purpose |
|---|---|
| `TOKEN_COOKIE` | shared session cookie name (`_ECHOcommunity_shared_session`) |
| `SESSION_NAMESPACE` | Redis key prefix for the main site's sessions (`shared_sessions`) |
| `USER_DB_REDIS_HOST` / `USER_DB_REDIS_PORT` | the shared session store |
| `USER_DB_REDIS_DB` | *(optional)* Redis logical db for the session store (prod = 0) |
| `USER_DB_REDIS_READONLY` | *(optional)* `true` makes the plugin never write to the shared store — used by staging to safely read prod sessions |

## Compatibility & branches
- **Discourse v2026.1 (ESR)** — Rails 8 / Ruby 3.4.
- **Production branch: `v2026.1-compat`** (currently v2.5.5) — this is what the deploy clones.
- Key v2026.1 specifics handled here: `DiscourseConnect.new(server_session:)` (renamed from
  `secure_session:`), the `ServerSession` class (renamed from `SecureSession`), and an explicit
  `require_dependency "auth/current_user_provider"` (the provider is subclassed at load time,
  before Zeitwerk eager-loading).
- ⚠️ `master` is legacy (pre‑2026). The live code is on **`v2026.1-compat`**.

## Installation
In the Discourse container config / CloudFormation `after_code` hook:
```yaml
- git clone --branch v2026.1-compat https://github.com/ECHOInternational/discourse-echo-login.git
```

## Notes
- It deserializes the **main site's** Rack session, so it depends on ECHOcommunity keeping
  `Marshal` session serialization (the `redis-store` default) — don't switch the main site's
  session serializer without updating this plugin.
- Don't remove the `require_dependency` line — without it v2026.1 boot fails with
  `uninitialized constant Auth::CurrentUserProvider`.
