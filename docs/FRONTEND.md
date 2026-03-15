# Static Asset Build — Tailwind CSS + DaisyUI

The frontend uses **Tailwind CSS v3** and **DaisyUI v4** as self-hosted CSS.  
No CDN is used. No frontend framework (React, Vue, etc.) is involved.

## How it works

The Tailwind CLI scans all HTML templates and generates a single minified CSS file:

```
frontend/static/src/input.css   ← Tailwind directives (source, not served)
        ↓  npm run build:css
frontend/static/vendor/bundle.css  ← compiled output, served by FastAPI at /static/vendor/bundle.css
```

All 13 HTML templates load:
```html
<link href="/static/vendor/bundle.css" rel="stylesheet" type="text/css" />
```

## Prerequisites

- [Node.js](https://nodejs.org/) (any LTS version, 18+)
- `npm` (included with Node.js)

Node is **only needed to rebuild CSS** — it is not running alongside the Python/FastAPI server.

## First-time setup

```bash
# Install Tailwind CLI + DaisyUI (saved to node_modules/, not shipped)
npm install
```

## Build the CSS bundle

```bash
# One-time / after changing templates or upgrading packages
npm run build:css
```

This produces `frontend/static/vendor/bundle.css`. Commit this file so the app
works in production without needing npm.

## Watch mode (during template development)

```bash
# Rebuilds automatically whenever a .html template is saved
npm run watch:css
```

## Upgrading DaisyUI or Tailwind

```bash
npm install tailwindcss@latest daisyui@latest
npm run build:css
# Test visually, then commit the updated bundle.css
```

## Adding a new theme

Edit [`tailwind.config.js`](../tailwind.config.js) and add the theme name to
the `daisyui.themes` array, then rebuild:

```js
daisyui: {
  themes: ["cupcake", "dracula", "your-new-theme"],
}
```

```bash
npm run build:css
```

## Deployment scenarios

### No frontend changes

If you **haven't modified any HTML templates** and **haven't upgraded packages**, there is **nothing to do**:

- `frontend/static/vendor/bundle.css` is already built and committed
- The app works out-of-the-box on production/deployment
- No `npm install` or `npm run build:css` required

Just start the FastAPI server. The pre-built CSS bundle is served automatically.

### Frontend changes (templates or packages)

If you **modify any HTML template** or **upgrade Tailwind/DaisyUI**, you must rebuild:

#### 1. Modified templates only (no package upgrades)

```bash
npm run build:css
```

The Tailwind CLI scans all templates and regenerates `frontend/static/vendor/bundle.css` with the exact same versions.

#### 2. Upgraded packages

```bash
npm install tailwindcss@latest daisyui@latest  # or specify versions
npm run build:css
git add frontend/static/vendor/bundle.css package.json package-lock.json
git commit -m "Upgrade Tailwind/DaisyUI and rebuild CSS bundle"
```

Always **test the updated bundle visually** before committing — verify:
- Page layouts render correctly
- DaisyUI components (buttons, cards, modals, etc.) display properly
- Theme toggle works (cupcake ↔ dracula)
- No visual regressions

#### 3. During development (templates changing frequently)

Use watch mode to auto-rebuild as you edit:

```bash
npm run watch:css
```

This monitors all HTML files in `frontend/templates/` and regenerates `bundle.css` whenever you save a template. Stop with `Ctrl+C`.

## Files

| File | Purpose | Committed? |
|------|---------|------------|
| `package.json` | npm manifest, build scripts | ✅ Yes |
| `tailwind.config.js` | Tailwind/DaisyUI config | ✅ Yes |
| `frontend/static/src/input.css` | Tailwind entry point | ✅ Yes |
| `frontend/static/vendor/bundle.css` | Built output | ✅ Yes (so no npm needed on deploy) |
| `node_modules/` | Build tooling | ❌ No (in .gitignore) |

---

## Form Validation & Input Constraints

### Organization Name
- **Maximum length**: 20 characters (enforced via `maxlength="20"`)
- **Real-time counter**: Shows "X/20 characters" as user types
- **Constraint label**: Form explicitly states "Max 20 characters"
- **Location**: [landing.html](../frontend/templates/landing.html#L333-L347) org creation modal

### Subject Alternative Names (SANs) - Server Certificates
Server certificates support SAN validation with real-time visual feedback:

**Supported types**:
- **DNS**: Domain names, FQDNs, wildcards (`*.example.com`)
  - Pattern: alphanumeric, hyphens, dots
  - Labels: max 63 chars each, max 253 total
  - Wildcards only allowed as first label
- **IP**: IPv4 (0-255 per octet) and IPv6 addresses
  - Validated with regex + octet range checks
- **EMAIL**: Basic email format (`user@domain.tld`)
- **URI**: Must start with valid scheme (`http://`, `https://`, `ldap://`, `ldaps://`, `ftp://`, `ftps://`)

**Real-time feedback**:
- ✅ **Green border** (`input-success`) when value is valid
- ❌ **Red border** (`input-error`) when value is invalid
- 🔧 Validation updates as user types (on `input` event)
- 🔄 Validation re-checks when SAN type selector changes

**Form-level validation**:
- Submit button prevents submission if any SAN has red border
- Error alert displays: "Please fix SAN entries (marked in red) before submitting."
- Alert auto-dismisses after 5 seconds

**Location**: [create_certificate.html](../frontend/templates/create_certificate.html#L513-L569) end-entity form, SAN section

### Policy-Driven Form Defaults
Certificate creation forms load cryptographic defaults from [`backend/config/policy.json`](../backend/config/policy.json):

- **Days to expiry**: Pre-filled per certificate type (root/intermediate/server/client/email/ocsp)
- **EC Curve**: Default curve displayed in select option text
- **Root password length**: Root CA form enforces the minimum length defined by `role_defaults.root.ROOT_PASSWORD_LENGTH`
- **Dynamic updates**: Days and curve refresh when switching between end-entity types

**Example**: Switching from "Server" to "Client" cert type:
- Days input changes from 825 to 802
- EC curve option text changes from "secp256r1" to "secp384r1"

**Location**: [create_certificate.html](../frontend/templates/create_certificate.html#L468-L488) end-entity type selector
