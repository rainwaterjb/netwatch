/* NetWatch themes. Loaded first by every page so the right colors paint before anything else.
   A theme only sets CSS variables; the pages use those variables for every color. */
(function () {
  "use strict";
  var THEMES = {
    "control-room": {"name": "Control Room", "mode": "dark", "note": "Today's look. Calm dark, blue accent.", "bg": "#0b0f14", "panel": "#11161d", "line": "#1f2731", "text": "#e6edf3", "muted": "#8b98a5", "free": "#1a212b", "green": "#3fb950", "red": "#f85149", "amber": "#d29922", "violet": "#a371f7", "accent": "#58a6ff", "ink": "#06121f", "cbOn": "#5aa9ff", "cbOff": "#f0883e", "font": "Inter", "mono": "JetBrains Mono", "radius": 8},
    "daylight": {"name": "Daylight", "mode": "light", "note": "Bright and crisp for daytime and offices.", "bg": "#f6f8fa", "panel": "#ffffff", "line": "#d0d7de", "text": "#1f2328", "muted": "#59636e", "free": "#eef1f4", "green": "#1a7f37", "red": "#cf222e", "amber": "#9a6700", "violet": "#8250df", "accent": "#0969da", "ink": "#ffffff", "cbOn": "#0969da", "cbOff": "#b35000", "font": "Inter", "mono": "JetBrains Mono", "radius": 8},
    "oled": {"name": "OLED Black", "mode": "dark", "note": "True black. Saves battery on phone screens.", "bg": "#000000", "panel": "#0b0b0c", "line": "#232326", "text": "#f5f5f7", "muted": "#9d9da3", "free": "#161618", "green": "#30d158", "red": "#ff453a", "amber": "#ffb340", "violet": "#bf5af2", "accent": "#64d2ff", "ink": "#00121a", "cbOn": "#64d2ff", "cbOff": "#ff9f0a", "font": "Inter", "mono": "JetBrains Mono", "radius": 12},
    "fjord": {"name": "Fjord", "mode": "dark", "note": "Soft slate blues. Easy on the eyes at night.", "bg": "#1e2430", "panel": "#262d3a", "line": "#3a4354", "text": "#e8ecf2", "muted": "#a9b3c4", "free": "#303848", "green": "#a3d48a", "red": "#f4908a", "amber": "#ecc985", "violet": "#c8acea", "accent": "#88c4d6", "ink": "#0f1f27", "cbOn": "#8fc1ff", "cbOff": "#f0b070", "font": "Inter", "mono": "JetBrains Mono", "radius": 10},
    "paper": {"name": "Paper", "mode": "light", "note": "Warm off-white, like a printed report.", "bg": "#f3eee4", "panel": "#fbf8f2", "line": "#ddd3c1", "text": "#2b2620", "muted": "#675d51", "free": "#ebe3d3", "green": "#2f6f2c", "red": "#ad3a28", "amber": "#7f5a00", "violet": "#744a9e", "accent": "#a8481f", "ink": "#ffffff", "cbOn": "#1f5fa8", "cbOff": "#a24a00", "font": "IBM Plex Sans", "mono": "IBM Plex Mono", "radius": 6},
    "phosphor": {"name": "Phosphor", "mode": "dark", "note": "Retro green terminal. All monospace.", "bg": "#040904", "panel": "#0a120a", "line": "#1d3a1d", "text": "#b8f5b2", "muted": "#79b873", "free": "#122012", "green": "#4cff6a", "red": "#ff6b5f", "amber": "#ffcc33", "violet": "#d4a0ff", "accent": "#4cff6a", "ink": "#021006", "cbOn": "#66ccff", "cbOff": "#ffaa33", "font": "JetBrains Mono", "mono": "JetBrains Mono", "radius": 2},
    "ember": {"name": "Ember", "mode": "dark", "note": "Warm charcoal with an orange glow.", "bg": "#14100d", "panel": "#1c1612", "line": "#382b22", "text": "#f4eae2", "muted": "#b4a191", "free": "#271e18", "green": "#82c97b", "red": "#ff6f61", "amber": "#f2a640", "violet": "#d6a1f2", "accent": "#ff8c42", "ink": "#1a0c03", "cbOn": "#6fb3ff", "cbOff": "#ffb347", "font": "Inter", "mono": "JetBrains Mono", "radius": 10},
    "synthwave": {"name": "Synthwave", "mode": "dark", "note": "Neon purple and pink. For the fun of it.", "bg": "#130e22", "panel": "#1b1530", "line": "#33295a", "text": "#f3ecff", "muted": "#ab9fcc", "free": "#251d40", "green": "#3ef0b0", "red": "#ff5c8a", "amber": "#ffc65c", "violet": "#b78fff", "accent": "#ff5ad9", "ink": "#1a0016", "cbOn": "#5ab8ff", "cbOff": "#ffa94d", "font": "Space Grotesk", "mono": "JetBrains Mono", "radius": 14},
    "lagoon": {"name": "Lagoon", "mode": "light", "note": "Cool aqua light theme, fresh and airy.", "bg": "#ecf5f5", "panel": "#ffffff", "line": "#c9dfdf", "text": "#0f2e2d", "muted": "#4a6766", "free": "#deeded", "green": "#1b7346", "red": "#bb2d3b", "amber": "#855600", "violet": "#6a45bd", "accent": "#0c7377", "ink": "#ffffff", "cbOn": "#0b5cad", "cbOff": "#a54f00", "font": "Inter", "mono": "JetBrains Mono", "radius": 12},
    "contrast": {"name": "High Contrast", "mode": "dark", "note": "Maximum legibility. Bold outlines.", "bg": "#000000", "panel": "#000000", "line": "#ffffff", "text": "#ffffff", "muted": "#e6e6e6", "free": "#262626", "green": "#3dff73", "red": "#ff7070", "amber": "#ffd60a", "violet": "#d7b4ff", "accent": "#ffd60a", "ink": "#000000", "cbOn": "#73c2ff", "cbOff": "#ffb000", "font": "Inter", "mono": "JetBrains Mono", "radius": 4},
    "neon-grid": {"name": "Neon Grid", "mode": "dark", "note": "Black glass, cyan light lines, orange warnings.", "bg": "#010409", "panel": "#050d14", "line": "#0e4a5c", "text": "#dcfbff", "muted": "#7fbccb", "free": "#0a1b24", "green": "#4dffb0", "red": "#ff6a3d", "amber": "#ffb627", "violet": "#c7a2ff", "accent": "#2ee6ff", "ink": "#00161b", "cbOn": "#79b8ff", "cbOff": "#ff9a1f", "font": "Exo 2", "mono": "JetBrains Mono", "radius": 2, "glow": "0 0 14px rgba(46,230,255,.22)"}
  };
  var FONTS = {
    "Inter": "inter-latin-wght-normal.woff2", "JetBrains Mono": "jetbrains-mono-latin-wght-normal.woff2",
    "Space Grotesk": "space-grotesk-latin-wght-normal.woff2", "Exo 2": "exo-2-latin-wght-normal.woff2",
    "IBM Plex Sans": "ibm-plex-sans-latin-wght-normal.woff2"
  };
  var CACHE = "netwatch.appearance";
  var css = Object.keys(FONTS).map(function (f) {
    return "@font-face{font-family:'" + f + "';font-style:normal;font-display:swap;font-weight:100 900;src:url(/fonts/" + FONTS[f] + ") format('woff2')}";
  }).join("") +
    "@font-face{font-family:'IBM Plex Mono';font-style:normal;font-display:swap;font-weight:400;src:url(/fonts/ibm-plex-mono-latin-400-normal.woff2) format('woff2')}" +
    "@font-face{font-family:'IBM Plex Mono';font-style:normal;font-display:swap;font-weight:500 700;src:url(/fonts/ibm-plex-mono-latin-500-normal.woff2) format('woff2')}";
  var style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  var DEFAULTS = { theme: "control-room", status_colors: "standard", follow_system: false,
                   light_theme: "daylight", dark_theme: "control-room" };
  var current = null;
  var dark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function read() {
    try { return JSON.parse(localStorage.getItem(CACHE) || "null"); } catch (e) { return null; }
  }
  function write(p) {
    try { localStorage.setItem(CACHE, JSON.stringify(p)); } catch (e) { /* private mode: fine */ }
  }
  function pick(p) {
    if (p.follow_system && dark) return dark.matches ? p.dark_theme : p.light_theme;
    return p.theme;
  }
  function apply(prefs) {
    var p = {};
    Object.keys(DEFAULTS).forEach(function (k) { p[k] = prefs && prefs[k] != null ? prefs[k] : DEFAULTS[k]; });
    current = p;
    var id = THEMES[pick(p)] ? pick(p) : DEFAULTS.theme, t = THEMES[id];
    var cb = p.status_colors === "colorblind";
    var v = {
      "--bg": t.bg, "--panel": t.panel, "--line": t.line, "--text": t.text, "--muted": t.muted, "--free": t.free,
      "--green": cb ? t.cbOn : t.green, "--red": cb ? t.cbOff : t.red, "--amber": t.amber, "--violet": t.violet,
      "--accent": t.accent, "--ink": t.ink, "--radius": t.radius + "px", "--glow": t.glow || "none",
      "--bw": id === "contrast" ? "2px" : "1px",
      "--font": "'" + t.font + "', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
      "--mono": "'" + t.mono + "', ui-monospace, SFMono-Regular, Menlo, monospace"
    };
    var root = document.documentElement;
    Object.keys(v).forEach(function (k) { root.style.setProperty(k, v[k]); });
    root.style.colorScheme = t.mode;
    root.setAttribute("data-theme", id);
    root.setAttribute("data-status-colors", cb ? "colorblind" : "standard");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", t.bg);
    write(p);
    return id;
  }
  if (dark && dark.addEventListener) {
    dark.addEventListener("change", function () { if (current && current.follow_system) apply(current); });
  }
  window.NetWatchTheme = {
    themes: THEMES, apply: apply,
    current: function () { return current; },
    active: function () { return current ? pick(current) : DEFAULTS.theme; }
  };
  apply(read());
})();
