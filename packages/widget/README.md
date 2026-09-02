# @quad4/ravenguard-widget

Privacy-first proof-of-work captcha widget for RavenGuard.

## Install

```bash
pnpm add @quad4/ravenguard-widget
```

```ts
import '@quad4/ravenguard-widget'
```

```html
<rg-check challenge="https://example.com/_rg/v1/challenge"></rg-check>
```

The default custom element is `rg-check`. Importing the package also registers `ravenguard-widget` as an alias. `register(tag)` can define additional tags.

```ts
import { register, RavenGuardWidget, RGCheck } from '@quad4/ravenguard-widget'

register('my-check')
```

`RGCheck` is an alias of the `RavenGuardWidget` class.

Hidden input name defaults to `rg`. Override with the `name` attribute.

Theme via `theme="light"`, `theme="dark"`, `theme="auto"`, or CSS variables on the host (`--rg-bg`, `--rg-fg`, `--rg-accent`, or page `--bg`, `--fg`, `--accent`).

Or load the IIFE build (`RGCheck` global):

```html
<script src="/path/to/w.js"></script>
```

The npm package also ships `dist/ravenguard-widget.min.js` (same obfuscated IIFE).

## Secure context

Uses Web Crypto. Serve over HTTPS (or localhost).
