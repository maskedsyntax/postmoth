// The suggestion chip: a closed shadow root the page cannot read or style,
// placed just below the field. Accepting requires a trusted (real user)
// click or key press.

const CSS = `
:host { all: initial; }
.chip {
  position: fixed; z-index: 2147483647; display: flex; align-items: center; gap: 4px;
  padding: 4px 4px 4px 10px; border-radius: 8px; box-sizing: border-box;
  font: 13px/1.3 system-ui, sans-serif; color: #1d1d1f; background: #ffffff;
  border: 1px solid #c8c8cc; box-shadow: 0 2px 10px rgba(0,0,0,.18);
}
@media (prefers-color-scheme: dark) {
  .chip { color: #f2f2f7; background: #2c2c2e; border-color: #48484a; }
  button.dismiss { color: #c7c7cc; }
}
button { font: inherit; border: 0; border-radius: 6px; cursor: pointer; }
button.fill { padding: 4px 10px; background: #3a6df0; color: #fff; font-weight: 600; }
button.fill:focus-visible, button.dismiss:focus-visible { outline: 2px solid #3a6df0; outline-offset: 2px; }
button.dismiss { padding: 2px 6px; background: transparent; color: #5c5c60; font-size: 16px; }
.label { white-space: nowrap; }
`;

export interface ChipCallbacks {
  onAccept(): void;
  onDismiss(): void;
}

export class Chip {
  private readonly host: HTMLElement;
  private readonly box: HTMLDivElement;
  private readonly fillButton: HTMLButtonElement;
  private readonly reposition = () => this.place();
  private readonly onKey = (ev: KeyboardEvent) => {
    // ArrowDown from the field moves focus to the chip.
    if (ev.isTrusted && ev.key === "ArrowDown" && ev.target === this.anchor) {
      ev.preventDefault();
      this.fillButton.focus();
    }
  };
  private readonly timer: ReturnType<typeof setTimeout>;

  constructor(
    readonly anchor: HTMLElement,
    label: string,
    callbacks: ChipCallbacks,
    lifetimeMs: number,
  ) {
    this.host = document.createElement("postmoth-suggestion");
    const root = this.host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = CSS;
    this.box = document.createElement("div");
    this.box.className = "chip";
    this.box.setAttribute("role", "dialog");
    this.box.setAttribute("aria-label", "Postmoth suggestion");

    const text = document.createElement("span");
    text.className = "label";
    text.textContent = label;

    this.fillButton = document.createElement("button");
    this.fillButton.className = "fill";
    this.fillButton.type = "button";
    this.fillButton.textContent = "Fill";
    this.fillButton.addEventListener("click", (ev) => {
      if (ev.isTrusted) callbacks.onAccept();
    });

    const dismiss = document.createElement("button");
    dismiss.className = "dismiss";
    dismiss.type = "button";
    dismiss.textContent = "×";
    dismiss.setAttribute("aria-label", "Dismiss");
    dismiss.addEventListener("click", (ev) => {
      if (ev.isTrusted) callbacks.onDismiss();
    });

    this.box.append(text, this.fillButton, dismiss);
    root.append(style, this.box);
    document.documentElement.append(this.host);
    this.place();
    window.addEventListener("scroll", this.reposition, true);
    window.addEventListener("resize", this.reposition);
    document.addEventListener("keydown", this.onKey, true);
    this.timer = setTimeout(() => callbacks.onDismiss(), lifetimeMs);
  }

  isFor(el: Element): boolean {
    return el === this.anchor;
  }

  private place(): void {
    const r = this.anchor.getBoundingClientRect();
    const top = Math.min(r.bottom + 6, window.innerHeight - 44);
    const left = Math.max(4, Math.min(r.left, window.innerWidth - 260));
    this.box.style.top = `${Math.max(4, top)}px`;
    this.box.style.left = `${left}px`;
  }

  remove(): void {
    clearTimeout(this.timer);
    window.removeEventListener("scroll", this.reposition, true);
    window.removeEventListener("resize", this.reposition);
    document.removeEventListener("keydown", this.onKey, true);
    this.host.remove();
  }
}
