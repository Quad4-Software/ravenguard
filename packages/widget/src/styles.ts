export const styles = `
:host {
  display: block;
  font-family: var(--rg-font, 'IBM Plex Sans', 'Segoe UI', sans-serif);
  color: var(--rg-fg, var(--fg, #e8e8e8));
  box-sizing: border-box;
}

:host *,
:host *::before,
:host *::after {
  box-sizing: border-box;
}

:host([theme='light']) {
  --rg-bg: #f5f5f5;
  --rg-fg: #1a1a1a;
  --rg-accent: #333333;
  --rg-border: #c8c8c8;
  --rg-ok: #3d8a3d;
  --rg-err: #a84848;
}

:host([theme='dark']) {
  --rg-bg: #121212;
  --rg-fg: #e8e8e8;
  --rg-accent: #c4c4c4;
  --rg-border: #2a2a2a;
  --rg-ok: #7dba7d;
  --rg-err: #c07070;
}

.rg-root {
  background: var(--rg-bg, var(--bg, #121212));
  border: 1px solid var(--rg-border, var(--border, #2a2a2a));
  border-radius: 6px;
  padding: 0.75rem 1rem;
  min-height: 2.75rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.rg-check {
  width: 1.25rem;
  height: 1.25rem;
  border: 2px solid var(--rg-accent, var(--accent, #c4c4c4));
  border-radius: 3px;
  flex-shrink: 0;
  display: grid;
  place-items: center;
  cursor: pointer;
  background: transparent;
  color: inherit;
  padding: 0;
  margin: 0;
  font-size: 0.65rem;
  font-weight: 700;
  line-height: 1;
  appearance: none;
  -webkit-appearance: none;
}

.rg-check:disabled {
  cursor: default;
}

.rg-check[data-state='verifying'] {
  border-color: transparent;
  background: transparent;
  cursor: wait;
}

.rg-check[data-state='verified'] {
  border-color: var(--rg-ok, #7dba7d);
  background: var(--rg-ok, #7dba7d);
  color: #0a0a0a;
}

.rg-check[data-state='error'],
.rg-check[data-state='expired'] {
  border-color: var(--rg-err, #c07070);
}

.rg-label {
  font-size: 0.875rem;
  line-height: 1.3;
  flex: 1;
  min-width: 0;
}

.rg-spinner {
  display: block;
  width: 1rem;
  height: 1rem;
  border: 2px solid var(--rg-border, var(--border, #2a2a2a));
  border-top-color: var(--rg-accent, var(--accent, #c4c4c4));
  border-radius: 50%;
  animation: rg-spin 0.7s linear infinite;
}

@keyframes rg-spin {
  to { transform: rotate(360deg); }
}

:host([display='invisible']) .rg-root {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
}
`
