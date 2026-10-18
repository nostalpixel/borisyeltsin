# MCP endpoint

BorisYeltsin serves a [Model Context Protocol](https://modelcontextprotocol.io) endpoint at `/mcp`, so an AI agent such as Claude can answer "what renews when, and what does it cost" from the subscription ledger, and add a subscription when you tell it to.

The endpoint never reaches the vault. Passwords are decrypted only in a browser that holds a passphrase, so the server has nothing to hand an agent. The tools also leave out login hints, account card labels, payment methods and vault links.

## Connect

1. Open **Agents** in the app and create a token. Pick a lifetime of 7, 30 or 90 days, and tick **Can also add subscriptions** only if the agent should write.
2. Copy the token. It is shown once; the server keeps only its SHA-256.
3. Add the endpoint to your client. For Claude Code:

```bash
claude mcp add --transport http borisyeltsin https://boris.example.com/mcp \
  --header "Authorization: Bearer bey_..."
```

Any MCP client that speaks Streamable HTTP and can send a bearer header works the same way. The endpoint is stateless and answers with JSON. Give your agent [AGENT_INTEGRATION.md](AGENT_INTEGRATION.md): tool schemas, rules and examples written for it.

## Tools

| Tool | Access | What it returns |
|---|---|---|
| `monthly_bill` | read | Monthly total per currency and the subscriptions behind it, largest first. Optional `category`. Quarterly, annual and custom cycles are spread over a month. Currencies are never converted. |
| `upcoming_renewals` | read | Subscriptions renewing in the next `days` (default 30, up to 366), soonest first. Overdue ones have negative days. |
| `list_subscriptions` | read | Every subscription, optionally filtered by service name. |
| `add_subscription` | write tokens only | Adds a subscription to the named service, creating the service if no service has that name. Put the plan and seat count in `name`, for example `Team, 2 users`. Refuses when the name matches an archived service. |

A read-only token does not list `add_subscription` at all.

Examples of what to ask:

- "What is our total monthly subscription bill?"
- "What renews in the next two weeks?"
- "We added Claude for 2 users, renewal on 15 November, 400 USD a month. Add it."

## Permissions

A token acts as the person who created it, with that person's current role and grants:

- It sees only the services that person can see in the app.
- `add_subscription` follows the app's rules. The person must be able to edit the service; only admins and managers create services. A read-only member cannot create a write token.
- Revoking the person revokes all their tokens. Changing their role changes what their tokens can do on the next request.

## Limits and records

- At most 10 active tokens per person. Lifetime 1 to 90 days.
- 120 MCP requests per minute per token, and per client address before the token is checked. Failed bearer attempts are limited further per address. With `TRUST_PROXY=true` the address comes from `X-Forwarded-For`, so only enable it behind a proxy that overwrites that header.
- Tool errors the agent sees are short messages; database errors are logged on the server and reported as `internal error`.
- Creating and revoking a token is recorded in the audit log. Services and subscriptions an agent creates are recorded with `via: mcp` and the token's id. The token list shows when each token was last used.
- People revoke their own tokens on the Agents page; an admin can show and revoke everyone's.

## What a token risks

A token is a bearer credential that skips Authentik and its MFA check. Whoever holds it can read the ledger as you until it expires or is revoked, and with write access can add subscriptions. Keep it in your agent's configuration, not in chat or a repository. It cannot read or change passwords, keys, members or recovery.
