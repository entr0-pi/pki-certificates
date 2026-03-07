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
