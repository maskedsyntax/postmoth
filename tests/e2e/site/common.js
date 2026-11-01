// Records what the page sees so the e2e test can assert on it.
window.__submits = 0;
document.addEventListener("submit", (e) => { e.preventDefault(); window.__submits++; });
