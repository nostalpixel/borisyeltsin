# BorisYeltsin design

Calm, dense, modern product UI with a light seasoning of 90s pixel games and a terminal. The name is the joke; the interface is a serious tool for passwords and money. Decisions here come from the design review of 2026-10-17 (DR-1 to DR-14 in the go-live plan). Change this file first, then the code.

The app contains no national symbols, flags, buildings, people or banner art. `docs/main_banner.png` sets the mood for the repository only.

## Theme

Dark only in v1 (`color-scheme: dark`). Every color is a CSS variable in `web/src/theme.css`; components never use a literal color.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0E1424` | page |
| `--panel` | `#141B2E` | sidebar, top bar, table, dialogs |
| `--panel-2` | `#1A2238` | expanded rows, inputs, hover |
| `--line` | `#5B6B90` | 1px borders and row dividers (≥3:1 on `--bg`) |
| `--text` | `#F3E6CF` | primary text |
| `--muted` | `#A9B0C2` | secondary text, labels |
| `--primary` | `#A9433A` | primary buttons (text: `--text`) |
| `--primary-hover` | `#923629` | primary hover (darker keeps contrast) |
| `--alert` | `#F0665E` | danger text and borders only, always with ▲ or ✗ and words |
| `--warn` | `#E0A93B` | due soon, review, warnings, always with ● and words |
| `--ok` | `#86C29A` | success text, ✓ |
| `--focus` | `#E0A93B` | 2px square focus ring |

Primary and alert are different reds on purpose: "Add service" must never look like "Fingerprint changed".

Contrast: text tokens ≥4.5:1 on `--bg` and `--panel`; `--line` ≥3:1 on `--bg`. `web/src/theme.test.ts` checks the pairs.

## Type

Three faces, all SIL OFL 1.1, shipped inside the image (`@fontsource/*`), never fetched from a CDN.

| Role | Face | Where |
|---|---|---|
| Brand | Silkscreen 400 | the `BORISYELTSIN` wordmark only |
| UI and data | JetBrains Mono 400/600, tabular numerals | headings, labels, buttons, table data, numbers, hosts, logins, fingerprints, status line |
| Prose | IBM Plex Sans 400/600 | sentences: intros, warnings, dialog text, empty states |

Floors: 14px data, 12px uppercase labels with `0.08em` tracking, 16px prose on trust screens, 18px fingerprints that wrap only between groups. Headings sit closer to what follows than to what precedes.

## Shape and depth

Square corners, radius at most 2px. 1px borders. No shadows except dialogs (`0 8px 24px` black at 45%). No gradients, glow or blur.

## Retro budget (DR-9)

Allowed:
- The pixel wordmark with a 2px hard offset shadow in `--primary`.
- The `>_` status line in the footer. Its cursor blinks for about 2 seconds after an action and is steady otherwise.
- A 120ms row expand.
- 8-bit glyphs as status markers: ■ ▲ ● ✓ ✗.

Not allowed: CRT or scanline effects, glow, typewriter text, pixel type anywhere except the wordmark, sound. `prefers-reduced-motion` turns all motion off.

## Layout

- Sidebar (wordmark, Services / Vault / Team, categories with counts, user and Sign out) plus a top bar with breadcrumb and actions.
- The ledger is one bordered table. Rows are divided by 1px lines; an expanded row shows an inset account sub-table. No card grids, no nested cards (DR-8).
- Summary numbers are one mono line under the title, never boxed tiles.
- Panels are for one focused task: sign-in, enrollment, dialogs.
- Vault: locked state, then tabs Items / Members / Recovery. Team: tabs People / Invitations / Keys / Audit (DR-1, PR2).
- Auth screens: wordmark, tagline "Everything is under control. Allegedly.", the step rail `[1 invite] ─ [2 key] ─ [3 approval]` (PR2), then one panel (DR-2, DR-14).

## States (DR-3)

Errors about keys and access render inline next to what failed, in `--alert` with ▲ and one action. Toasts and the status line are for neutral confirmations only. Empty states say what is missing and offer the next action. The full per-feature table lives in the go-live plan.

## Trust screens

Recovery key shown once, fingerprint verification, pending approval and recovery each get their own screen or dialog with 16px prose and 18px grouped mono values (DR-4 to DR-7, PR2/PR3). Confirmation means typing the last group, never a lone OK.

## Responsive and accessibility (DR-13)

- Below 760px the sidebar becomes a top bar with Services / Vault / Team and a visible Sign out.
- Ledger rows stack as "name / due · cost"; host and accounts move into the expanded row.
- Auth and trust dialogs go full screen.
- Touch targets are at least 44px.
- Every input has a visible label. Errors link with `aria-describedby`. Busy and success messages go to a polite live region. Dialogs trap and return focus.
- Check at 320px wide and at 200% zoom.
