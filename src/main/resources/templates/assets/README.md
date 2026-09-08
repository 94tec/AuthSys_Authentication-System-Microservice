# Email assets

The spec lists `logo.png`, `footer-pattern.png`, and `icons/` (raster images).
Raster PNGs can't be meaningfully generated as code — they need an actual
designer or an image-generation tool pointed at your real logo — so this
folder contains **SVG placeholders** instead:

- `logo.svg` — simple "Damuchi" wordmark placeholder, replace with your real logo
- `footer-pattern.svg` — a subtle dotted divider in the coral tone
- `icons/facebook.svg`, `icons/instagram.svg`, `icons/x.svg` — simple circular social icons

**Important for real email sending:** most email clients (Outlook in particular)
render SVG `<img>` sources unreliably or not at all. Before going live:

1. Export each SVG here to PNG (e.g. via a design tool, or `rsvg-convert`/`inkscape`
   in a build step) at 2x resolution for retina screens.
2. Host the PNGs on a public CDN/static host and point `logoUrl` etc. at those URLs.
3. Or, for the social icons specifically, the inline circular-badge markup already
   used in `components/social-links.html` works without any image at all — it's
   pure CSS/HTML and renders identically everywhere. Keep that version unless you
   have real brand-specific icon art to swap in.
