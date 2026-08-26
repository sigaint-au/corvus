<!--
impeccable:design-schema 1
schema: design
surface: web
mode: operate
-->

# Corvus — Design System

## Visual Identity

Corvus is a secrets manager built for engineering teams who treat infrastructure security as a first-class concern. The visual language reflects that: no decoration, no flourish, no color that doesn't carry meaning. Every surface earns its place by being legible, scannable, and trustworthy at a glance.

The brand mark is a raven — `app/static/logo.svg` — rendered as a CSS mask in the sidebar and auth card header. It inverts with color-scheme (black on light, cream on dark). The raven is the only ornamental element in the entire interface.

### Design Principles

1. **Monochrome authority.** Pure black and white are the primary palette. Color is reserved for semantic states (danger, success, warning) and a single teal accent in the sidebar. No gradients on content surfaces, no decorative color.
2. **Tonal layering over shadows.** Depth is communicated through background tone (`--faint` → `--muted` → `--secondary` → `--card` → `--background`) rather than box shadows. Shadows appear only on floating elements (dialogs, auth cards).
3. **Density with breath.** Compact spacing for data surfaces (tables, secret lists), generous padding for decision surfaces (empty states, setup guide, auth). The interface respects the operator's screen real estate.
4. **Monospace where it matters.** Secret keys, values, and all cryptographic material use the monospace stack. Prose uses the system sans. The typographic shift signals "this is data, not narrative."
5. **Plain copy.** User-facing text is direct and factual. RBAC role names appear verbatim. No marketing voice inside the product.

## Color System

All tokens use `light-dark()` for dual-theme support. The sidebar is always dark regardless of color-scheme — it acts as a fixed shell.

### Surface Tokens

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
| `--faint-foreground` | `#64707c` | `#737a84` | Faintest text |
| `--accent` | `#eef0f1` | `#1a1e22` | Accent surfaces |
| `--border` | `#d4d4d8` | `#2a2f34` | Borders, dividers |
| `--input` | `#d4d4d8` | `#2a2f34` | Input borders |
| `--ring` | `#000000` | `#f5f5f5` | Focus ring (pure black/white) |

### Semantic Tokens

| Token | Light | Dark | Usage |
|-------|-------|------|-------|
| `--danger` | `#d32f2f` | `#f4807b` | Destructive actions, overdue, errors |
| `--danger-foreground` | `#ffffff` | `#18181b` | Text on danger surfaces |
| `--success` | `#008032` | `#6cc070` | Success states |
| `--success-foreground` | `#ffffff` | `#0a0a0a` | Text on success surfaces |
| `--warning` | `#a65b00` | `#f0a030` | Warnings, expiring soon |
| `--warning-foreground` | `#000000` | `#000000` | Text on warning surfaces |

### Sidebar Tokens (always dark)

| Token | Value | Usage |
|-------|-------|-------|
| `--side-bg` | `#0c0e10` | Sidebar background |
| `--side-ink` | `#e8eaed` | Sidebar primary text |
| `--side-muted` | `#9aa1a9` | Sidebar secondary text |
| `--side-faint` | `#6b727a` | Sidebar faint text |
| `--side-hover` | `#161a1f` | Sidebar hover background |
| `--side-active` | `#1a2228` | Sidebar active link background |
| `--side-accent` | `#47817F` | Teal accent (active step, focus) |
| `--side-border` | `#252a30` | Sidebar borders |
| `--side-input` | `#121518` | Sidebar input background |
| `--side-w` | `15.5rem` | Sidebar width |

### Accent Rule

`--side-accent` (`#47817F` teal) is the only non-monochrome, non-semantic color in the system. It appears exclusively in the sidebar shell and the setup-guide active step. It never appears in content surfaces, buttons, or data tables. Success green is deliberately distinct from the teal accent — the CSS comment makes this explicit: "Success must read as success, not brand teal."

## Typography

### Font Families

- **Sans (body, UI):** `var(--font-sans)` from oat.ink — system font stack (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`)
- **Monospace (secrets, keys, code):** `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`

No web fonts are loaded. The system stack ensures zero latency and native rendering on every platform.

### Type Scale

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
| Body text | oat default (1rem) | 400 | |
| Muted text | .9rem | 400 | `--muted-foreground` |
| Radio-card help | .8rem | 400 | `--muted-foreground` |
| Labels/legends | .72rem | 650 | letter-spacing .04em, uppercase |
| Brand sub | .68rem | 500 | letter-spacing .05em, uppercase |

### Typographic Conventions

- Secret keys and values render in `<code class="k">` with monospace font
- Masked secrets use `•••••••` with letter-spacing .08em
- Labels and legends are uppercase, small, tight letter-spacing — functional, not decorative
- RBAC role names appear verbatim in badges, never translated or prettified

## Spacing & Radius

### Radius

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | 4px | Small controls, tight corners |
| `--radius` | 8px | Default — cards, inputs, radio cards, list panels |
| `--radius-lg` | 12px | Auth card, dialogs |

### Spacing Patterns

- Page padding: oat default (content area has comfortable margins)
- List panel padding: 1.1rem
- Empty state padding: 2.5rem 1rem
- Card/dialog form padding: 1rem 1.15rem (header), .5rem gap (footer)
- Field grid: 2-column, .65rem row gap, .85rem column gap
- Sidebar padding: 1.1rem .7rem 1rem
- Section gap (settings-form): 1.15rem

## Layout

### App Shell

The authenticated app uses a two-column grid: fixed sidebar (`--side-w: 15.5rem`) + fluid content area. The sidebar is `position: sticky` and always dark. Below 720px the sidebar collapses to a toggle with backdrop overlay.

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

### Auth Shell

Unauthenticated pages use a centered auth card (max-width 22rem) on a dot-pattern background. If a login banner is configured, the layout splits `1fr 2fr` (max 1000px) with the banner in the aside.

```
┌────────────────────────────────┐
│  · · · · · · · (dot pattern) ·  │
│  ┌──────────────────┐           │
│  │  Raven mark       │           │
│  │  Corvus           │  banner   │
│  │  ─────────────    │  (opt.)   │
│  │  form fields      │           │
│  └──────────────────┘           │
│  · · · · · · · · · · · · · · ·  │
└────────────────────────────────┘
```

### Resource Sub-Pages

Team and project detail pages use a vertical rail (`page-side` / `page-subnav`) with `?tab=` links. The tab nav markup (`nav.tabs`) is used only for client-side widget tablists (e.g. role-create mode switcher).

### Responsive Breakpoints

| Breakpoint | What changes |
|------------|-------------|
| `max-width: 720px` | Sidebar collapses to toggle+backdrop; field-grid → 1 col; auth-split → 1 col |
| `max-width: 640px` | Token-policy-grid → 1 col |
| `max-width: 600px` | Token-policy-grid → 1 col (duplicate) |

720px is the primary structural breakpoint. Below it, the app is single-column with a hamburger sidebar.

## Components

### App Shell & Sidebar

Dark slate (`#0c0e10`), always dark regardless of theme. Contains: brand mark (raven via CSS mask), global search, team selector dropdown, collapsible nav groups (`<details>`), pinned items, recent secrets, user email + logout. Sidebar width is 15.5rem. Nav links use `.12s ease` hover transition to `--side-hover` background.

### Auth Card

Centered, max-width 22rem, card background, 1px border, `--radius-lg` (12px), subtle shadow (`0 1px 3px rgba(0,0,0,.06)`). Sits on a radial-gradient dot-pattern background (`rgba(0,0,0,.08)` 1px dots, 22px grid). Optional split view with login banner aside.

### List Panel

Card surface for tabular data: `--card` background, 1px `--border`, `--radius`, 1.1rem padding. Contains tables (wrapped in `.table` div for horizontal scroll on narrow screens) or empty states.

### Empty State

Reusable partial (`partials/empty_state.html`): centered flex column, 58px circle art with gradient background, title (1.04rem/650), muted text (.9rem, max 30rem), optional CTA button. Icons: folder, teams, key, search, inbox, default. Used across teams, projects, secrets, and members lists.

### Setup Guide

First-run onboarding panel on the teams page (shown when `can_create_team` and no teams exist). Three numbered steps with the current step highlighted via `--side-accent` border and filled circle. Guides the user through: Create team → Create project → Add secret.

### Radio Cards

Used for encryption selection and other mutually exclusive choices. Flex row, 1px border, `--radius`, `.85rem 1rem` padding. Checked state via `:has(input:checked)`: border becomes `--ring`, background becomes `--muted`, box-shadow `0 0 0 1px var(--ring)`. Optional `.radio-card-help` text (.8rem, muted) explains tradeoffs.

### Dialogs

`<dialog>` elements with `data-open-dialog`/`data-close-dialog` triggers. Max-width `min(24rem, 100vw-2rem)`, 1px border, `--radius-lg`, `--card` background, moderate shadow (`0 8px 24px rgb(0 0 0 / .15)`). Form header padding 1rem 1.15rem, footer flex with .5rem gap.

### Badges

oat.ink `.badge` component with `data-variant` attribute: `secondary` (role names, kind chips), `danger` (overdue, destructive), `warning` (expiring soon, rotation due), `success` (active states). Badges are the primary way RBAC roles and secret metadata are communicated inline.

### Secret Masked

Monospace, .9em, letter-spacing .08em, muted color, .3rem .45rem padding. Renders as `•••••••` when not revealed. Locked secrets show a lock icon badge; access-granted secrets show a clock badge.

### Buttons

Provided by oat.ink framework. Variants: primary (solid `--primary`), outline (border + ghost), ghost (transparent), small (size modifier). No custom button CSS in app.css. Used consistently for CTAs, form submits, and toolbar actions.

### Forms

`.settings-form` is a flex column with 1.15rem gap. `.field-grid` is a 2-column grid (collapses to 1 col on mobile). `.field-group` wraps related fields with a 1px border, `--radius`, `.85rem 1rem` padding, and an uppercase legend. CSRF tokens on all POST forms.

### Flash Messages

oat.ink alerts via `partials/flash_messages.html` with `data-variant` for success/error/warning/info. Server-rendered, appear at top of content area.

### HTMX Loading States

Elements with HTMX get `.12s ease` opacity transition to .45–.55, `pointer-events: none`. The secrets list shows a spinner (`secrets-spin` keyframe, .6s linear rotate).

## Motion

Motion is restrained and functional. No decorative animations.

| Pattern | Duration | Easing | Usage |
|---------|----------|--------|-------|
| Color transition | .12s | ease | Border, background, opacity on hover/focus |
| HTMX loading | .12s | ease | Opacity fade to .45–.55 |
| Spinner | .6s | linear | Secrets list spinner (rotate) |

No motion tokens defined. All transitions are inline `.12s ease`. No entrance animations, no scroll-triggered effects, no parallax.

## Elevation

| Element | Shadow | Notes |
|---------|--------|-------|
| Auth card | `0 1px 3px rgba(0,0,0,.06)` | Minimal lift |
| Dialog | `0 8px 24px rgb(0 0 0 / .15)` | Moderate lift for floating UI |
| Radio card checked | `0 0 0 1px var(--ring)` | Ring, not shadow |
| Everything else | none | Flat — depth via tonal layering |

## Framework

### oat.ink

The project uses [oat.ink](https://oat.ink) as its CSS/JS foundation (`app/static/vendor/oat.min.css`, `app/static/vendor/oat.min.js`). oat provides:

- Base reset and typography scale
- Button component (primary, outline, ghost, small variants)
- Badge component (data-variant driven)
- Input/select/textarea base styles
- Table styles (with `.table` wrapper for horizontal scroll)
- Alert component (flash messages)
- Menu/dropdown primitives

`app.css` (3088 lines) is the Corvus theme layer on top of oat. It defines all custom properties, the app shell, sidebar, auth card, radio cards, empty states, setup guide, dialogs, secret-specific UI, and responsive overrides. No utility framework (Tailwind, etc.) is used.

### HTMX

HTMX (`app/static/vendor/htmx.min.js`) handles partial-page updates. Secret lists, search, tab switches, and pin toggles use HTMX. The server returns partials (Jinja2 templates in `app/templates/partials/`). Loading states are CSS-driven (opacity + spinner).

### JavaScript

`app/static/app.js` provides: CSRF token injection for HTMX requests, sidebar group persistence (localStorage), mobile sidebar toggle, user autocomplete (datalist). No client-side framework. No onboarding tour JS.

## Iconography

All icons are inline SVGs with `stroke="currentColor"`, `stroke-width="1.5"`, `fill="none"`. They are functional, not decorative — search, key, folder, teams, inbox, lock, clock, hamburger menu. No icon font, no icon library. The raven brand mark is the only non-geometric SVG.

## Accessibility

- Skip link to `#main-content` in base.html
- `aria-hidden="true"` on decorative SVGs and the brand logo
- `aria-label` on icon-only buttons and table header columns
- `aria-current="page"` on active sidebar links
- `role="search"` on search forms
- `visually-hidden` class for screen-reader-only labels
- Focus ring uses pure black/white (`--ring`), high contrast in both themes
- Dialogs use native `<dialog>` with `closedby="any"`
- No established accessibility standard in PRODUCT.md — this is the incumbent state, not a commitment
