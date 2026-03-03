(function () {
  const KEY = "pki-theme";
  const LIGHT_THEME = "cupcake";
  const DARK_THEME = "dracula";
  const DEFAULT_THEME = LIGHT_THEME;

  function applyTheme(theme) {
    const selected = (theme === DARK_THEME || theme === LIGHT_THEME) ? theme : DEFAULT_THEME;
    document.documentElement.setAttribute("data-theme", selected);
    return selected;
  }

  function buildToggle(currentTheme) {
    const wrap = document.createElement("div");
    wrap.id = "theme-toggle-wrap";
    wrap.style.position = "fixed";
    wrap.style.right = "12px";
    wrap.style.bottom = "12px";
    wrap.style.zIndex = "9999";
    wrap.style.display = "flex";
    wrap.style.alignItems = "center";
    wrap.style.padding = "2px";
    wrap.style.borderRadius = "9999px";
    wrap.style.background = "transparent";
    wrap.style.border = "none";
    wrap.style.boxShadow = "none";

    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-ghost btn-xs";
    button.style.opacity = "0.7";
    button.style.minHeight = "1.5rem";
    button.style.height = "1.5rem";
    button.style.paddingLeft = "0.5rem";
    button.style.paddingRight = "0.5rem";
    button.textContent = currentTheme === DARK_THEME ? "Light Mode" : "Dark Mode";

    button.addEventListener("click", function () {
      const now = document.documentElement.getAttribute("data-theme");
      const nextTheme = now === DARK_THEME ? LIGHT_THEME : DARK_THEME;
      const next = applyTheme(nextTheme);
      localStorage.setItem(KEY, next);
      button.textContent = next === DARK_THEME ? "Light Mode" : "Dark Mode";
    });

    wrap.appendChild(button);
    document.body.appendChild(wrap);
  }

  const saved = localStorage.getItem(KEY) || DEFAULT_THEME;
  const current = applyTheme(saved);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      buildToggle(current);
    });
  } else {
    buildToggle(current);
  }
})();
