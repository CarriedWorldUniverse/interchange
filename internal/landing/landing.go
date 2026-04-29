// Package landing serves a minimal HTML landing page for humans who
// browse the public URL. The interchange is content-blind transit
// infrastructure; the landing page exists so a passing browser doesn't
// see Go's default 404 (which leaks framework identity) and so a human
// who finds the URL can tell what it is.
//
// Intentionally reveals nothing operational: no interchange_id, no
// version, no internal endpoints beyond what /.well-known/nexus-interchange
// already publishes.
//
// Design (per operator #8192): the SVG fills the viewport as a fixed
// full-bleed background; type sits over it like an engineering-drawing
// stamp in the lower-left, with metadata anchored lower-right.
// Lowercase title. Refined minimalism. JetBrains Mono throughout.
//
// SVG by maren — content-blind relay between two paired endpoints,
// ciphertext blocks visible inside the rotated-diamond relay symbol.
package landing

import (
	"net/http"
	"strings"
)

// Handler returns the landing page handler. Only matches the exact
// path "/"; any other path falls through to the next mux entry (or
// 404 from the default mux). MethodNotAllowed for non-GET.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only match the literal root. Without this, "/" in a ServeMux
		// would also catch unmatched paths like "/foo" because Go's
		// default mux treats "/" as a prefix.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		// CSP: inline styles only (single-page restraint permits this).
		// Allow Google Fonts for JetBrains Mono — fonts.googleapis.com
		// for the CSS, fonts.gstatic.com for the woff2.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; "+
				"style-src 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write([]byte(pageHTML))
	}
}

// pageHTML is the static landing page. Single response, no external
// resources except the JetBrains Mono webfont. SVG by maren is inlined
// verbatim inside the .bg container.
var pageHTML = strings.TrimLeft(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>interchange</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@200;400&display=swap">
<style>
  :root {
    /* Match the SVG's own background fill (#080c10) so the
       letterbox/pillarbox area when the SVG scales with 'meet'
       reads as a continuous field, not a band. */
    --bg: #080c10;
    --fg: #d8dee4;
    --dim: #5a6878;
    --hairline: #1a242f;
    --accent: #6ec1ff;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    height: 100%;
    background: var(--bg);
    color: var(--fg);
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-weight: 200;
    overflow: hidden;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  /* Background SVG — full bleed, fixed, behind everything. */
  .bg {
    position: fixed;
    inset: 0;
    z-index: 0;
    opacity: 0;
    animation: bgIn 1.6s cubic-bezier(.2, .65, .25, 1) 0.1s forwards;
  }
  .bg svg {
    width: 100%;
    height: 100%;
    display: block;
  }

  /* Edge vignette — preserves the endpoint nodes (which live ~16%
     and ~84% horizontally in the SVG) at full read while calming the
     true corners. Wider transparent core (70%) and a gentler peak
     so the rings of both endpoints stay legible. */
  .vignette {
    position: fixed;
    inset: 0;
    z-index: 1;
    pointer-events: none;
    background: radial-gradient(ellipse 90% 75% at center,
      transparent 70%,
      rgba(6, 10, 14, 0.35) 92%,
      rgba(6, 10, 14, 0.65) 100%);
  }

  /* Film grain — fractal-noise SVG, blended for texture. */
  .grain {
    position: fixed;
    inset: 0;
    z-index: 2;
    pointer-events: none;
    opacity: 0.06;
    mix-blend-mode: overlay;
    background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/></filter><rect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/></svg>");
  }

  /* Engineering-drawing register marks at top corners. */
  .corner {
    position: fixed;
    z-index: 3;
    width: 18px;
    height: 18px;
    pointer-events: none;
    opacity: 0;
    animation: cornerIn 0.5s ease-out 1.6s forwards;
  }
  .corner::before, .corner::after {
    content: '';
    position: absolute;
    background: var(--hairline);
  }
  .corner::before { left: 0; top: 0; width: 100%; height: 1px; }
  .corner::after  { left: 0; top: 0; width: 1px; height: 100%; }
  .corner.tl { top: 24px; left: 24px; }
  .corner.tr { top: 24px; right: 24px; transform: scaleX(-1); }

  /* Stamp blocks — title bottom-left, metadata bottom-right. */
  .stamp {
    position: fixed;
    z-index: 3;
  }

  .stamp.id {
    bottom: 4vh;
    left: 4vw;
  }
  .stamp.id .name {
    display: block;
    font-size: clamp(2.5rem, 5.5vw, 4.5rem);
    font-weight: 200;
    letter-spacing: -0.02em;
    line-height: 0.9;
    color: var(--fg);
    transform: translateY(20px);
    opacity: 0;
    animation: stampIn 0.7s cubic-bezier(.2, .65, .25, 1) 0.9s forwards;
  }
  .stamp.id .desc {
    display: block;
    margin-top: 1rem;
    font-size: 0.78rem;
    font-weight: 400;
    letter-spacing: 0.04em;
    color: var(--dim);
    max-width: 38ch;
    transform: translateY(10px);
    opacity: 0;
    animation: stampIn 0.6s cubic-bezier(.2, .65, .25, 1) 1.2s forwards;
  }

  .stamp.meta {
    bottom: 4vh;
    right: 4vw;
    text-align: right;
    transform: translateY(10px);
    opacity: 0;
    animation: stampIn 0.6s cubic-bezier(.2, .65, .25, 1) 1.4s forwards;
  }
  .stamp.meta dl {
    display: grid;
    grid-template-columns: auto auto;
    column-gap: 1.2rem;
    row-gap: 0.4rem;
    font-size: 0.74rem;
    font-weight: 400;
    letter-spacing: 0.06em;
  }
  .stamp.meta dt {
    color: var(--dim);
    text-transform: uppercase;
    font-size: 0.66rem;
    letter-spacing: 0.12em;
    text-align: left;
  }
  .stamp.meta dd {
    color: var(--fg);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .stamp.meta dd a {
    position: relative;
    color: var(--fg);
    text-decoration: none;
  }
  .stamp.meta dd a::after {
    content: '';
    position: absolute;
    left: 0;
    bottom: -2px;
    width: 100%;
    height: 1px;
    background: var(--accent);
    transform: scaleX(0);
    transform-origin: right center;
    transition: transform 0.18s cubic-bezier(.2, .65, .25, 1);
  }
  .stamp.meta dd a:hover { color: var(--accent); }
  .stamp.meta dd a:hover::after {
    transform: scaleX(1);
    transform-origin: left center;
  }

  @keyframes bgIn {
    from { opacity: 0; transform: scale(1.04); }
    to   { opacity: 1; transform: scale(1); }
  }
  @keyframes stampIn {
    to { transform: translateY(0); opacity: 1; }
  }
  @keyframes cornerIn {
    to { opacity: 1; }
  }

  @media (max-width: 640px) {
    .stamp.meta {
      bottom: auto;
      top: 4vh;
    }
    .stamp.meta dl { font-size: 0.68rem; }
  }

  @media (prefers-reduced-motion: reduce) {
    .bg, .stamp .name, .stamp .desc, .stamp.meta, .corner {
      animation: none;
      opacity: 1;
      transform: none;
    }
  }
</style>
</head>
<body>
  <div class="bg" aria-hidden="true">
    <svg viewBox="0 0 1200 500" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <radialGradient id="bgA" cx="15%" cy="50%" r="45%">
          <stop offset="0%" stop-color="#0f1822" stop-opacity="1"/>
          <stop offset="100%" stop-color="#080c10" stop-opacity="1"/>
        </radialGradient>
        <radialGradient id="bgB" cx="85%" cy="50%" r="45%">
          <stop offset="0%" stop-color="#0f1822" stop-opacity="1"/>
          <stop offset="100%" stop-color="#080c10" stop-opacity="1"/>
        </radialGradient>
        <radialGradient id="nodeGlowA" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#b9c4d0" stop-opacity="0.07"/>
          <stop offset="100%" stop-color="#b9c4d0" stop-opacity="0"/>
        </radialGradient>
        <radialGradient id="relayGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#4a7fa8" stop-opacity="0.12"/>
          <stop offset="100%" stop-color="#4a7fa8" stop-opacity="0"/>
        </radialGradient>
        <linearGradient id="chanLeft" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#6ec1ff" stop-opacity="0.6"/>
          <stop offset="100%" stop-color="#6ec1ff" stop-opacity="0.25"/>
        </linearGradient>
        <linearGradient id="chanRight" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#6ec1ff" stop-opacity="0.25"/>
          <stop offset="100%" stop-color="#6ec1ff" stop-opacity="0.6"/>
        </linearGradient>
        <clipPath id="leftChan">
          <rect x="230" y="0" width="330" height="500"/>
        </clipPath>
        <clipPath id="rightChan">
          <rect x="640" y="0" width="330" height="500"/>
        </clipPath>
        <filter id="softBlur" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="1.2"/>
        </filter>
        <filter id="nodeGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="18"/>
        </filter>
        <filter id="relayGlowFilter" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="12"/>
        </filter>
      </defs>

      <rect width="1200" height="500" fill="#080c10"/>
      <rect x="0" y="0" width="600" height="500" fill="url(#bgA)"/>
      <rect x="600" y="0" width="600" height="500" fill="url(#bgB)"/>

      <g fill="#1e2d3d" opacity="0.9">
        <circle cx="72" cy="88" r="1"/><circle cx="144" cy="42" r="0.8"/>
        <circle cx="210" cy="130" r="1.2"/><circle cx="320" cy="68" r="0.8"/>
        <circle cx="390" cy="155" r="1"/><circle cx="450" cy="42" r="0.7"/>
        <circle cx="520" cy="110" r="1.1"/><circle cx="68" cy="330" r="0.9"/>
        <circle cx="155" cy="400" r="1"/><circle cx="240" cy="360" r="0.7"/>
        <circle cx="370" cy="420" r="1.2"/><circle cx="480" cy="380" r="0.8"/>
        <circle cx="530" cy="440" r="0.9"/><circle cx="680" cy="68" r="1"/>
        <circle cx="750" cy="130" r="0.8"/><circle cx="840" cy="52" r="1.1"/>
        <circle cx="910" cy="140" r="0.9"/><circle cx="990" cy="80" r="0.7"/>
        <circle cx="1070" cy="120" r="1"/><circle cx="1140" cy="60" r="0.8"/>
        <circle cx="670" cy="400" r="0.9"/><circle cx="780" cy="370" r="1"/>
        <circle cx="860" cy="430" r="0.7"/><circle cx="950" cy="390" r="1.2"/>
        <circle cx="1040" cy="440" r="0.8"/><circle cx="1130" cy="380" r="1"/>
        <circle cx="600" cy="30" r="0.9"/><circle cx="600" cy="470" r="0.9"/>
      </g>

      <g stroke="#111820" stroke-width="0.5" opacity="0.8">
        <line x1="0" y1="167" x2="1200" y2="167"/>
        <line x1="0" y1="333" x2="1200" y2="333"/>
        <line x1="400" y1="0" x2="400" y2="500"/>
        <line x1="800" y1="0" x2="800" y2="500"/>
      </g>

      <circle cx="195" cy="250" r="160" fill="url(#nodeGlowA)" filter="url(#nodeGlow)"/>
      <circle cx="195" cy="250" r="100" fill="none" stroke="#b9c4d0" stroke-width="0.4" opacity="0.12"/>
      <circle cx="195" cy="250" r="80" fill="none" stroke="#b9c4d0" stroke-width="0.5" opacity="0.18"/>
      <circle cx="195" cy="250" r="62" fill="none" stroke="#b9c4d0" stroke-width="1" opacity="0.45"/>
      <circle cx="195" cy="250" r="44" fill="none" stroke="#b9c4d0" stroke-width="1.4" opacity="0.7"/>
      <circle cx="195" cy="250" r="26" fill="none" stroke="#b9c4d0" stroke-width="2" opacity="0.9"/>
      <g stroke="#b9c4d0" stroke-width="0.8" opacity="0.35">
        <line x1="195" y1="200" x2="195" y2="180"/><line x1="195" y1="300" x2="195" y2="320"/>
        <line x1="145" y1="250" x2="125" y2="250"/><line x1="245" y1="250" x2="265" y2="250"/>
      </g>
      <circle cx="195" cy="250" r="4" fill="#b9c4d0" opacity="0.95"/>
      <circle cx="195" cy="250" r="2" fill="#e8edf2"/>
      <g stroke="#b9c4d0" stroke-width="1" opacity="0.4">
        <line x1="195" y1="186" x2="195" y2="179"/><line x1="195" y1="314" x2="195" y2="321"/>
        <line x1="133" y1="250" x2="126" y2="250"/><line x1="257" y1="250" x2="264" y2="250"/>
        <line x1="239" y1="206" x2="244" y2="201"/><line x1="151" y1="206" x2="146" y2="201"/>
        <line x1="239" y1="294" x2="244" y2="299"/><line x1="151" y1="294" x2="146" y2="299"/>
      </g>

      <circle cx="1005" cy="250" r="160" fill="url(#nodeGlowA)" filter="url(#nodeGlow)"/>
      <circle cx="1005" cy="250" r="100" fill="none" stroke="#b9c4d0" stroke-width="0.4" opacity="0.12"/>
      <circle cx="1005" cy="250" r="80" fill="none" stroke="#b9c4d0" stroke-width="0.5" opacity="0.18"/>
      <circle cx="1005" cy="250" r="62" fill="none" stroke="#b9c4d0" stroke-width="1" opacity="0.45"/>
      <circle cx="1005" cy="250" r="44" fill="none" stroke="#b9c4d0" stroke-width="1.4" opacity="0.7"/>
      <circle cx="1005" cy="250" r="26" fill="none" stroke="#b9c4d0" stroke-width="2" opacity="0.9"/>
      <g stroke="#b9c4d0" stroke-width="0.8" opacity="0.35">
        <line x1="1005" y1="200" x2="1005" y2="180"/><line x1="1005" y1="300" x2="1005" y2="320"/>
        <line x1="955" y1="250" x2="935" y2="250"/><line x1="1055" y1="250" x2="1075" y2="250"/>
      </g>
      <circle cx="1005" cy="250" r="4" fill="#b9c4d0" opacity="0.95"/>
      <circle cx="1005" cy="250" r="2" fill="#e8edf2"/>
      <g stroke="#b9c4d0" stroke-width="1" opacity="0.4">
        <line x1="1005" y1="186" x2="1005" y2="179"/><line x1="1005" y1="314" x2="1005" y2="321"/>
        <line x1="943" y1="250" x2="936" y2="250"/><line x1="1067" y1="250" x2="1074" y2="250"/>
        <line x1="1049" y1="206" x2="1054" y2="201"/><line x1="961" y1="206" x2="956" y2="201"/>
        <line x1="1049" y1="294" x2="1054" y2="299"/><line x1="961" y1="294" x2="956" y2="299"/>
      </g>

      <line x1="259" y1="240" x2="545" y2="240" stroke="#6ec1ff" stroke-width="0.4" opacity="0.15"/>
      <line x1="259" y1="260" x2="545" y2="260" stroke="#6ec1ff" stroke-width="0.4" opacity="0.15"/>
      <line x1="655" y1="240" x2="941" y2="240" stroke="#6ec1ff" stroke-width="0.4" opacity="0.15"/>
      <line x1="655" y1="260" x2="941" y2="260" stroke="#6ec1ff" stroke-width="0.4" opacity="0.15"/>

      <g clip-path="url(#leftChan)">
        <line x1="259" y1="250" x2="545" y2="250" stroke="url(#chanLeft)" stroke-width="1.5" stroke-dasharray="12 8"/>
        <g fill="#6ec1ff">
          <rect x="275" y="246" width="18" height="8" rx="1" opacity="0.22"/>
          <rect x="310" y="247" width="10" height="6" rx="1" opacity="0.16"/>
          <rect x="338" y="245" width="24" height="10" rx="1" opacity="0.18"/>
          <rect x="376" y="247" width="14" height="6" rx="1" opacity="0.14"/>
          <rect x="408" y="246" width="20" height="8" rx="1" opacity="0.20"/>
          <rect x="445" y="247" width="8" height="6" rx="1" opacity="0.13"/>
          <rect x="468" y="245" width="16" height="10" rx="1" opacity="0.17"/>
          <rect x="502" y="247" width="22" height="6" rx="1" opacity="0.19"/>
        </g>
      </g>

      <g clip-path="url(#rightChan)">
        <line x1="655" y1="250" x2="941" y2="250" stroke="url(#chanRight)" stroke-width="1.5" stroke-dasharray="12 8"/>
        <g fill="#6ec1ff">
          <rect x="668" y="247" width="8" height="6" rx="1" opacity="0.13"/>
          <rect x="692" y="245" width="22" height="10" rx="1" opacity="0.17"/>
          <rect x="730" y="247" width="16" height="6" rx="1" opacity="0.19"/>
          <rect x="760" y="246" width="12" height="8" rx="1" opacity="0.14"/>
          <rect x="792" y="247" width="20" height="6" rx="1" opacity="0.20"/>
          <rect x="826" y="245" width="10" height="10" rx="1" opacity="0.16"/>
          <rect x="855" y="247" width="24" height="6" rx="1" opacity="0.18"/>
          <rect x="895" y="246" width="14" height="8" rx="1" opacity="0.22"/>
          <rect x="924" y="247" width="8" height="6" rx="1" opacity="0.15"/>
        </g>
      </g>

      <circle cx="600" cy="250" r="120" fill="url(#relayGlow)" filter="url(#relayGlowFilter)"/>
      <polygon points="600,198 652,250 600,302 548,250" fill="none" stroke="#3d6b8a" stroke-width="1" opacity="0.5"/>
      <polygon points="600,218 632,250 600,282 568,250" fill="none" stroke="#4a8ab0" stroke-width="1.2" opacity="0.7"/>
      <polygon points="600,232 618,250 600,268 582,250" fill="#0c1820" stroke="#5ea0c8" stroke-width="1.6" opacity="0.9"/>
      <g filter="url(#softBlur)" opacity="0.6">
        <rect x="583" y="242" width="34" height="4" rx="0.5" fill="#2a4a62"/>
        <rect x="587" y="250" width="26" height="4" rx="0.5" fill="#2a4a62"/>
        <rect x="581" y="258" width="38" height="4" rx="0.5" fill="#2a4a62"/>
      </g>
      <g opacity="0.35">
        <rect x="583" y="242" width="34" height="4" rx="0.5" fill="#4a7fa8"/>
        <rect x="587" y="250" width="26" height="4" rx="0.5" fill="#4a7fa8"/>
        <rect x="581" y="258" width="38" height="4" rx="0.5" fill="#4a7fa8"/>
      </g>
      <g stroke="#3d6b8a" stroke-width="0.8" opacity="0.5">
        <line x1="600" y1="192" x2="600" y2="184"/><line x1="600" y1="308" x2="600" y2="316"/>
        <line x1="542" y1="250" x2="534" y2="250"/><line x1="658" y1="250" x2="666" y2="250"/>
      </g>
      <line x1="545" y1="250" x2="568" y2="250" stroke="#4a8ab0" stroke-width="1.5" opacity="0.6"/>
      <line x1="632" y1="250" x2="655" y2="250" stroke="#4a8ab0" stroke-width="1.5" opacity="0.6"/>
      <circle cx="568" cy="250" r="2.5" fill="#4a8ab0" opacity="0.8"/>
      <circle cx="632" cy="250" r="2.5" fill="#4a8ab0" opacity="0.8"/>
    </svg>
  </div>

  <div class="vignette" aria-hidden="true"></div>
  <div class="grain" aria-hidden="true"></div>

  <span class="corner tl" aria-hidden="true"></span>
  <span class="corner tr" aria-hidden="true"></span>

  <div class="stamp id">
    <span class="name">interchange</span>
    <span class="desc">A content-blind relay between paired agents. This server sees ciphertext only.</span>
  </div>

  <div class="stamp meta">
    <dl>
      <dt>protocol</dt><dd>nexus-frame-relay/1</dd>
      <dt>discovery</dt><dd><a href="/.well-known/nexus-interchange">/.well-known/nexus-interchange</a></dd>
      <dt>source</dt><dd><a href="https://github.com/nexus-cw/interchange">github.com/nexus-cw/interchange</a></dd>
    </dl>
  </div>
</body>
</html>
`, "\n")
