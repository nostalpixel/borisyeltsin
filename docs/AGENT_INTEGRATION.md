# BorisYeltsin: agent integration

This file is written for AI agents and the people wiring them up. It is self-contained: an agent can read it and use the BorisYeltsin MCP server without other documents. Human background is in [MCP.md](MCP.md).

## What this server is

BorisYeltsin is a subscription ledger for one organization: services (for example Linode, GitHub, Claude), their subscriptions, prices, billing cycles and renewal dates. The MCP server answers what renews when, and what it costs, and can add subscriptions.

It has no access to passwords, logins, payment cards or the encrypted vault. Do not offer to look those up; tell the user to open the app instead.

## Connection

| Field | Value |
|---|---|
| Endpoint | `https://<your BorisYeltsin host>/mcp` |
| Transport | MCP Streamable HTTP, stateless. POST only; responses are `application/json`. |
| Auth | `Authorization: Bearer bey_...` (personal agent token from the **Agents** page) |
| Server name | `borisyeltsin` |

A token acts as the person who created it and sees only the services they can see. Tokens expire after 7, 30 or 90 days. A read-only token does not list `add_subscription`.

### Claude Code, one command

```bash
claude mcp add --transport http borisyeltsin https://boris.example.com/mcp \
  --header "Authorization: Bearer $BORISYELTSIN_TOKEN"
```

### Project config (`.mcp.json`)

Keep the token in an environment variable, never in the file:

```json
{
  "mcpServers": {
    "borisyeltsin": {
      "type": "http",
      "url": "https://boris.example.com/mcp",
      "headers": { "Authorization": "Bearer ${BORISYELTSIN_TOKEN}" }
    }
  }
}
```

Any other MCP client that speaks Streamable HTTP and can send a header is configured the same way.

## Tools

All amounts are decimal strings with two decimals (`"400.00"`), in the subscription's own currency. Totals are per currency and are never converted. Dates are `YYYY-MM-DD` in the organization's time zone.

### `monthly_bill` (read)

Monthly cost per currency and the subscriptions behind it, largest first.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `category` | string | no | One of `infra`, `domains`, `tools`, `comms`, `partners`, `payments`, `other` |

Returns `monthly_total` (map of currency to amount), `subscriptions` (count) and `lines[]` with `service`, `name`, `billing_cycle`, `cost`, `monthly`, `currency`.

`monthly` spreads longer cycles over a month: quarterly cost / 3, annual cost / 12, custom cost × 30 / days. Say "about" when quoting a monthly figure for a non-monthly plan, and give the real price per cycle too.

### `upcoming_renewals` (read)

Subscriptions renewing within a window, soonest first.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `days` | integer | no | Look-ahead, 1 to 366, default 30 |

Returns `today` and `subscriptions[]`. Overdue subscriptions have a negative `days_until_renewal` and come first; auto-renewing ones move forward on their own within a minute of midnight, so an overdue entry usually means `auto_renew` is false.

### `list_subscriptions` (read)

Every subscription, optionally filtered.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `service` | string | no | Case-insensitive substring of the service name |

Returns `today` and `subscriptions[]`.

Each subscription in `upcoming_renewals` and `list_subscriptions` has: `id`, `service`, `category`, `name`, `billing_cycle`, `custom_interval_days` (custom only), `renewal_date`, `days_until_renewal`, `cost`, `monthly`, `currency`, `auto_renew`.

### `add_subscription` (write tokens only)

Adds a subscription. If no service has that name (case-insensitive), it creates the service.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `service` | string | yes | Service name, for example `Claude` |
| `cost` | string | yes | Price per billing cycle, for example `"400"` or `"19.99"` |
| `renewal_date` | string | yes | Next renewal, `YYYY-MM-DD` |
| `name` | string | no | Plan and seats, for example `"Team, 2 users"` |
| `billing_cycle` | string | no | `monthly` (default), `quarterly`, `annual`, `custom` |
| `custom_interval_days` | integer | only for `custom` | Days per cycle |
| `currency` | string | no | 3 to 5 capital letters, default `USD` |
| `auto_renew` | boolean | no | Default `true` |
| `category` | string | no | For a new service only; default `other` |

Returns `service_created` (boolean) and `subscription`.

## Rules for agents

1. **Confirm before writing.** Repeat the service, plan name, cost, currency, cycle and renewal date back to the user and wait for a yes before calling `add_subscription`. It cannot be undone through MCP; the user removes mistakes in the app.
2. **Resolve the date.** Turn "15 Nov" into a full date. If the year is ambiguous, pick the next 15 November from `today` (call `list_subscriptions` or `upcoming_renewals` to read `today`) and say which year you used.
3. **Cost is per billing cycle.** "400 a month" is `cost: "400"`, `billing_cycle: "monthly"`. "4,800 a year" is `cost: "4800"`, `billing_cycle: "annual"`. Do not pre-divide.
4. **Seats go in `name`.** There is no seat field. "Claude for 2 users" becomes `name: "Team, 2 users"` (or the plan the user named).
5. **Ask for the currency** when the user gives a bare number and the organization's other subscriptions use more than one currency. Otherwise reuse the currency they already use, or default to USD and say so.
6. **Check before adding.** Call `list_subscriptions` with the service name first. If a matching subscription already exists, ask whether this is a new one or a change; changes are made in the app.
7. **Never sum across currencies.** Report each currency total separately.
8. **No credentials.** Never ask the user for passwords or card numbers, and never put them in `name`; the server rejects anything that looks like a card number.

## Examples

**"What's our total monthly subscription bill?"**
Call `monthly_bill` with no arguments. Answer with each currency total and the three largest lines, for example: "840.00 USD a month across 3 subscriptions. Largest: Claude Team 400.00, Linode VPS 240.00, GitHub (annual 2,400.00, about 200.00 a month)."

**"What renews in the next two weeks?"**
Call `upcoming_renewals` with `{"days": 14}`. List each with date, days left, cost and currency; flag overdue ones.

**"We added a Claude subscription for 2 users, renews 15 Nov, 400 a month."**
1. `list_subscriptions` with `{"service": "Claude"}` to check for an existing one and read `today`.
2. Confirm: "Add Claude, Team, 2 users, 400.00 USD monthly, next renewal 2026-11-15, auto-renew on?"
3. On yes, call:

```json
{
  "service": "Claude",
  "name": "Team, 2 users",
  "cost": "400",
  "currency": "USD",
  "billing_cycle": "monthly",
  "renewal_date": "2026-11-15",
  "category": "tools"
}
```

4. Report the result, including whether the service was created.

## Errors

Tool errors come back as a tool result with `isError: true` and a short message. Show it to the user in plain words.

| Message | What to do |
|---|---|
| `invalid subscription: check cost, currency, billing_cycle, custom_interval_days and renewal_date` | Fix the argument (cost as a decimal string, date as `YYYY-MM-DD`, custom needs `custom_interval_days`). |
| `no service has that name, and only admins and managers can create one` | Ask an admin or manager to add the service in the app, or use an existing service name. |
| `you cannot edit this service` | The token's owner lacks edit rights on that service. |
| `a service with that name is archived; unarchive it in the app first` | Ask the user to unarchive it. |
| `several services have that name; rename one in the app first` | Ask the user to rename one. |
| `this looks like a full card number; ...` | Remove the number from `name`. |
| `internal error` | Server-side failure. Retry once later; otherwise tell the user. |

HTTP-level responses: `401` means the token is missing, wrong, expired or revoked (ask the user for a new one from the Agents page); `429` means more than 120 requests a minute (wait a minute); `405` for GET or DELETE (the server is stateless, use POST).
