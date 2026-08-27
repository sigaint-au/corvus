<!--
impeccable:design-schema 1
schema: design
surface: web
mode: operate
-->

# Corvus — Style Guide

A designer-facing reference for carrying Corvus's visual language into a new
project. Every value here is taken from the running implementation
(`app/static/app.css`, `app/static/logo.svg`, `app/static/favicon.svg`,
`app/templates/`). Where this guide differs from `DESIGN.md`, this guide is
current.

---

## 1. Identity

Corvus is a self-hosted secrets manager for engineering teams that treat
infrastructure security as a first-class concern. The visual language says
that plainly: no decoration, no flourish, no color that doesn't carry
meaning. Every surface earns its place by being legible, scannable, and
trustworthy at a glance.

The brand mark is a raven. It is the only ornamental element in the entire
interface.

### Design principles

1. **Monochrome authority.** Pure black and white are the primary palette.
   Color is reserved for semantic states (danger, success, warning) and a
   single teal accent in the sidebar. No gradients on content surfaces, no
   decorative color.
2. **Tonal layering over shadows.** Depth comes from background tone
   (`--faint` → `--muted` → `--secondary` → `--card` → `--background`), not
   box shadows. Shadows appear only on floating elements (dialogs, auth card).
3. **Density with breath.** Compact spacing for data surfaces (tables, secret
   lists), generous padding for decision surfaces (empty states, setup guide,
   auth). Respect the operator's screen real estate.
4. **Monospace where it matters.** Secret keys, values, and all cryptographic
   material use the monospace stack. Prose uses the system sans. The shift
   signals "this is data, not narrative."
5. **Plain copy.** User-facing text is direct and factual. RBAC role names
   appear verbatim. No marketing voice inside the product.

---

## 2. Color system

All tokens are defined once in `:root` using `light-dark()` so light and dark
themes share one source. The sidebar is always dark regardless of color-scheme
— it acts as a fixed shell.

### Surface tokens

| Token | Light | Dark | Usage |
|-------|-------|------|-------|
| `--background` | `#ffffff` | `#0a0a0a` | Page background |
| `--foreground` | `#000000` | `#f5f5f5` | Primary text |
| `--card` | `#ffffff` | `#141414` | Cards, list panels, dialogs |
| `--card-foreground` | `#000000` | `#f5f5f5` | Text on cards |
| `--primary` | `#000000` | `#f5f5f5` | Primary buttons, focus ring |
| `--primary-foreground` | `#ffffff` | `#000000` | Text on primary buttons |
| `--secondary` | `#f4f5f6` | `#1c1f23` | Secondary surfaces |
| `--secondary-foreground` | `#677381` | `#a3a9b0` | Muted labels on secondary |
| `--muted` | `#f0f1f2` | `#181b1e` | Muted backgrounds |
| `--muted-foreground` | `#57626e` | `#a3aab3` | Secondary text, hints |
| `--faint` | `#fafafa` | `#111111` | Faintest surface tier |
| `--faint-foreground` | `#5a6670` | `#838a98` | Faintest text |
| `--accent` | `#eef0f1` | `#1a1e22` | Accent surfaces |
| `--border` | `#d4d4d8` | `#2a2f34` | Borders, dividers |
| `--input` | `#d4d4d8` | `#2a2f34` | Input borders |
| `--ring` | `#000000` | `#f5f5f5` | Focus ring (pure black/white) |

### Semantic tokens

| Token | Light | Dark | Usage |
|-------|-------|------|-------|
| `--danger` | `#d32f2f` | `#f4807b` | Destructive actions, overdue, errors |
| `--danger-foreground` | `#ffffff` | `#18181b` | Text on danger surfaces |
| `--success` | `#008032` | `#6cc070` | Success states |
| `--success-foreground` | `#ffffff` | `#0a0a0a` | Text on success surfaces |
| `--warning` | `#a65b00` | `#f0a030` | Warnings, expiring soon |
| `--warning-foreground` | `#000000` | `#000000` | Text on warning surfaces |

### Sidebar tokens (always dark)

| Token | Value | Usage |
|-------|-------|-------|
| `--side-bg` | `#0c0e10` | Sidebar background |
| `--side-ink` | `#e8eaed` | Sidebar primary text |
| `--side-muted` | `#9aa1a9` | Sidebar secondary text |
| `--side-faint` | `#828a92` | Sidebar faint text (passes AA on `--side-bg`) |
| `--side-brand` | `#f4f1ea` | Brand mark cream in the sidebar |
| `--side-hover` | `#161a1f` | Sidebar hover background |
| `--side-active` | `#1a2228` | Sidebar active link background |
| `--side-accent` | `#47817F` | Teal accent (active step, focus) |
| `--side-border` | `#252a30` | Sidebar borders |
| `--side-input` | `#121518` | Sidebar input background |
| `--side-w` | `15.5rem` | Sidebar width |

### The accent rule

`--side-accent` (`#47817F` teal) is the only non-monochrome, non-semantic
color in the system. It appears exclusively in the sidebar shell and the
setup-guide active step. It never appears in content surfaces, buttons, or
data tables. Success green is deliberately distinct from the teal accent:
success must read as success, not brand.

### Contrast floor

Every text token pair passes WCAG AA (4.5:1) in both themes. The tightest
pairs, verified:

- `--muted-foreground` on `--background`: ~6.2:1 light, ~7.8:1 dark
- `--side-faint` (`#828a92`) on `--side-bg` (`#0c0e10`): ~4.6:1
- `--faint-foreground` on `--faint`: ~4.5:1+ both themes

Do not darken these values. They sit at the AA boundary.

---

## 3. Typography

### Font families

- **Sans (body, UI):** the oat.ink `--font-sans` system stack —
  `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Monospace (secrets, keys, code):** `ui-monospace, SFMono-Regular, Menlo,
  Consolas, monospace`

No web fonts are loaded. The system stack gives zero latency and native
rendering on every platform. Carry this forward: do not introduce webfonts
for a product in this family.

### Type scale

| Element | Size | Weight | Notes |
|---------|------|--------|-------|
| h1 (page) | 1.5rem | 600 | letter-spacing -.02em |
| h1 (auth card) | 1.35rem | 600 | |
| h2 (section) | 1.05rem | 600 | |
| h3 | oat default | — | |
| Empty-state title | 1.04rem | 650 | |
| Setup-guide title | 1.04rem | 650 | |
| Radio-card label | .95rem | 600 | |
| Brand text | .95rem | 700 | letter-spacing -.02em |
| Body text | 1rem | 400 | oat default |
| Muted text | .9rem | 400 | `--muted-foreground` |
| Radio-card help | .8rem | 400 | `--muted-foreground` |
| Labels/legends | .72rem | 650 | letter-spacing .04em, uppercase |
| Brand sub | .68rem | 500 | letter-spacing .05em, uppercase |

### Typographic conventions

- Secret keys and values render in `<code class="k">` with the monospace stack
- Masked secrets use `•••••••` with letter-spacing .08em
- Labels and legends are uppercase, small, tight letter-spacing — functional,
  not decorative
- RBAC role names appear verbatim in badges, never translated or prettified
- The `.muted` class sets `--muted-foreground` at .9em

---

## 4. Logo and wordmark

### The raven mark

`app/static/logo.svg` — a single-path raven on a 500×474 canvas. It inverts
with color-scheme: `#0c0c0b` (near-black) in light mode, `#f4f1ea` (cream)
in dark mode.

The mark renders three ways:

1. **CSS mask (primary).** The `.brand-logo` class paints a
   `background-color: currentColor` box and masks it with the SVG:
   `mask: url("logo.svg") center / contain no-repeat`. Color comes from the
   surrounding context — sidebar uses `--side-brand`, auth uses
   `light-dark(#0c0c0b, var(--side-brand))`. This lets the mark inherit hover
   and theme states without duplicating assets.
2. **Inline SVG.** Used in email and static contexts where masks are
   unreliable.
3. **Favicon.** `app/static/favicon.svg` — the raven in cream on a
   `#0c0c0b` rounded-square tile (32×32, rx=7). This tile is the app icon
   pattern: near-black tile, cream mark.

### Sizes

| Context | Size |
|---------|------|
| Sidebar brand | 1.5rem wide, height `1.5rem × 474/500` |
| Auth brand | 2.15rem wide, height `2.15rem × 474/500` |
| Favicon | 32×32 |

Height always follows the 500:474 canvas ratio. Never distort the mark.

### Wordmark

The wordmark is typeset, not drawn:

- **Sidebar:** brand text `.95rem / 700`, letter-spacing -.02em, in
  `--side-ink`. Optional sub-line `.68rem / 500`, uppercase, letter-spacing
  .05em, in `--side-faint` (e.g. the tagline).
- **Auth:** brand text `1.05rem / 700` in `--foreground`, centered under the
  mark. Sub-line `.7rem / 500`, uppercase, in `--muted-foreground`.
- The mark is `aria-hidden` when it sits beside the wordmark; the wordmark is
  the accessible name.

The default product name is **Corvus**, but the name is configurable
(`brand_name` setting). The style must survive any name.

---

## 5. Layout

### App shell

Two-column grid: fixed sidebar (`--side-w: 15.5rem`) + fluid content area.
Sidebar is `position: sticky` and always dark.

```
┌─────────────┬──────────────────────────┐
│             │  page-head               │
│  Sidebar    │  page-desc               │
│  (dark,     │  ─────────────────────  │
│   sticky)   │  list-panel / form /     │
│             │  settings-form           │
│  - brand    │                          │
│  - search   │                          │
│  - team     │                          │
│  - nav      │                          │
│  - pins     │                          │
│  - recent   │                          │
│  - user     │                          │
└─────────────┴──────────────────────────┘
```

Sidebar anatomy: brand lockup, global search, team selector dropdown,
collapsible nav groups (`<details>`), pinned items, recent secrets, user
email + logout.

### Auth shell

Unauthenticated pages use a centered auth card (max-width 22rem) on a
dot-pattern background — a radial-gradient of 1px `rgba(0,0,0,.08)` dots on a
22px grid. With a login banner configured, the layout splits `1fr 2fr`
(max 1000px).

### Resource sub-pages

Team and project detail pages use a vertical rail (`page-side` /
`page-subnav`) with `?tab=` links. The rail is an 11rem column; on mobile
(≤720px) it becomes a horizontal wrapping row. Underline tabs (`.tabs`) are
for server-side section navigation and client-side widget tablists only.

### Responsive breakpoints

| Breakpoint | What changes |
|------------|-------------|
| `max-width: 720px` | Sidebar collapses to a 2.75rem toggle + backdrop; field-grid → 1 col; auth-split → 1 col; subnav rail → horizontal |
| `max-width: 640px` | Token-policy grid → 1 col |

720px is the primary structural breakpoint. Below it the app is single-column
with a hamburger sidebar. Tables never break: they sit inside a `.table`
wrapper that scrolls horizontally.

---

## 6. Spacing and radius

### Radius

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | 4px | Small controls, tight corners |
| `--radius` | 8px | Default — cards, inputs, radio cards, list panels |
| `--radius-lg` | 12px | Auth card, dialogs |

### Spacing patterns

- Page padding: oat default (content area has comfortable margins)
- List panel padding: 1.1rem
- Empty state padding: 2.5rem 1rem
- Dialog header: 1rem 1.15rem; footer: flex with .5rem gap
- Field grid: 2 columns, .65rem row gap, .85rem column gap
- Sidebar padding: 1.1rem .7rem 1rem
- Settings form section gap: 1.15rem

---

## 7. Components

### List panel

Card surface for tabular data: `--card` background, 1px `--border`,
`--radius`, 1.1rem padding. Contains tables (wrapped in `.table`) or empty
states. A bare table is also valid — a table with nothing else does not need
a panel around it.

### Empty state

Centered flex column: 58px circle art with a subtle gradient background,
title (1.04rem/650), muted text (.9rem, max-width 30rem), optional CTA.
Icons: folder, teams, key, search, inbox, default.

### Setup guide

First-run onboarding panel. Numbered steps with the current step highlighted
via `--side-accent` border and filled circle.

### Radio cards

Mutually exclusive choices (e.g. encryption selection). Flex row, 1px border,
`--radius`, `.85rem 1rem` padding. Checked state via `:has(input:checked)`:
border becomes `--ring`, background becomes `--muted`, plus a 1px ring shadow.
Optional `.radio-card-help` (.8rem, muted) explains tradeoffs.

### Dialogs

Native `<dialog>` with `closedby="any"`. Max-width `min(24rem, 100vw-2rem)`,
1px border, `--radius-lg`, `--card` background, shadow
`0 8px 24px rgb(0 0 0 / .15)`.

### Badges

oat.ink `.badge` with `data-variant`: `secondary` (role names, kind chips),
`danger` (overdue, destructive), `warning` (expiring soon), `success`
(active). Badges are the primary way RBAC roles and secret metadata are
communicated inline. Variants are driven by `data-variant`, never by class
names.

### Buttons

oat.ink framework. Variants: primary (solid `--primary`), outline (border +
transparent bg), ghost (transparent), small (size modifier). No custom button
CSS. In filter/toolbar rows, buttons are height-matched to inputs
(`min-height: calc(1.5em + 1rem + 2px)`).

### Forms

`.settings-form` is a flex column with 1.15rem gap. `.field-grid` is a
2-column grid (1 col on mobile) with `.span-2` full-width rows. `.field-group`
wraps related fields: 1px border, `--radius`, `.85rem 1rem` padding, uppercase
legend. `.field-hint` (.75rem/500/muted) explains a single field. `.check-row`
is a labeled checkbox row. Every POST form carries a CSRF token.

### Secret value surfaces

Revealed secret values sit on a `--muted` readout surface in monospace, with
horizontal scroll rather than truncation. Masked values use `•••••••` at .9em
with letter-spacing .08em.

### Flash messages

oat.ink alerts via `data-variant` (success/error/warning/info), server-
rendered at the top of the content area.

---

## 8. Motion and elevation

### Motion

Restrained and functional. No decorative animation.

| Pattern | Duration | Easing | Usage |
|---------|----------|--------|-------|
| Color transition | .12s | ease | Border, background, opacity on hover/focus |
| HTMX loading | .12s | ease | Opacity fade to .45–.55 |
| Spinner | .6s | linear | Secrets list spinner (rotate) |

`prefers-reduced-motion: reduce` collapses durations to .01ms but keeps state
change visible — the spinner still appears, forms still dim. Do not ship a
global motion kill that destroys feedback.

### Elevation

| Element | Shadow |
|---------|--------|
| Auth card | `0 1px 3px rgba(0,0,0,.06)` |
| Dialog | `0 8px 24px rgb(0 0 0 / .15)` |
| Radio card checked | `0 0 0 1px var(--ring)` (ring, not shadow) |
| Everything else | none — depth via tonal layering |

---

## 9. Iconography

All icons are inline SVGs: `stroke="currentColor"`, `stroke-width="1.5"`,
`fill="none"`. Functional, not decorative — search, key, folder, teams,
inbox, lock, clock, hamburger. No icon font, no icon library. The raven is
the only non-geometric SVG in the product.

---

## 10. Voice and copy

- Direct, factual, plain. No marketing voice inside the product.
- RBAC role names appear verbatim (`team-owner`, `service-read`).
- Error and empty states say what happened and what to do next.
- Labels are short and specific; hints are one clause.

---

## 11. Accessibility

- Skip link to `#main-content`
- `aria-hidden="true"` on decorative SVGs and the brand mark beside a
  wordmark
- `aria-label` on icon-only buttons and action table columns
- `aria-current="page"` on active nav links
- `role="search"` on search forms
- Focus ring is `--ring` (pure black/white), high contrast in both themes
- Touch targets: primary controls ≥ 2.25rem (36px); the sidebar toggle is
  2.75rem
- Headings descend without skipping levels (h1 → h2 → h3)
- `role="alert"` for live errors; `role="status"` for the error-page code

---

## 12. Technical foundation

- **oat.ink** (`vendor/oat.min.css`, `vendor/oat.min.js`) provides the base
  reset, typography scale, buttons, badges, inputs, tables, alerts, and
  dropdowns. `app.css` is the theme layer on top — all custom properties, the
  shell, sidebar, and product components.
- **HTMX** for partial-page updates; loading states are CSS-driven.
- **No utility framework.** No Tailwind, no component library, no webfonts.
- **One CSS file.** `app.css` (~3,200 lines) is organized by component with
  section comments.
- **Dual theme** via `color-scheme: light dark` and `light-dark()` tokens —
  no separate dark stylesheet.

---

## 13. Carrying this to a new project

A checklist for a designer starting fresh:

1. Copy the `:root` token block verbatim (surface, semantic, sidebar). It is
   the whole palette.
2. Keep the accent rule: one teal, sidebar-only, never in content.
3. Use the system font stacks. Do not add webfonts.
4. Render the raven as a CSS mask with `currentColor`; keep the 500:474 ratio.
5. Build depth with tonal layering, not shadows. Shadows only on floating
   elements.
6. Use oat.ink (or an equivalent classless base) + a single theme CSS file.
7. Ship both themes from one token source with `light-dark()`.
8. Keep motion at .12s ease and honor `prefers-reduced-motion`.
9. Respect the contrast floor for `--muted-foreground`, `--side-faint`, and
   `--faint-foreground`.
10. Monospace for data, sans for prose. Uppercase micro-labels for structure.
11. Plain copy, verbatim role names, no decoration.