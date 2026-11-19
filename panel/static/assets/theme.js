(() => {
  const key = "psiphon3xui-theme";
  const root = document.documentElement;

  function applyTheme(theme) {
    const selected = theme === "dark" ? "dark" : "light";
    root.dataset.theme = selected;
    document.querySelectorAll("[data-theme-toggle]").forEach(toggle => {
      const nextLabel = selected === "dark" ? "Switch to light theme" : "Switch to dark theme";
      toggle.setAttribute("aria-pressed", String(selected === "dark"));
      toggle.setAttribute("aria-label", nextLabel);
      toggle.title = nextLabel;
    });
  }

  try {
    const saved = localStorage.getItem(key);
    if (saved === "dark" || saved === "light") applyTheme(saved);
    else applyTheme(root.dataset.theme);
  } catch (_) {
    applyTheme(root.dataset.theme);
  }

  document.addEventListener("click", event => {
    const toggle = event.target.closest?.("[data-theme-toggle]");
    if (!toggle) return;
    const selected = root.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(selected);
    try { localStorage.setItem(key, selected); } catch (_) {}
  });
})();
