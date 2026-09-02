<script lang="ts">
  interface Props {
    label: string
    value: number
    display?: string
    tone?: 'default' | 'ok' | 'warn' | 'bad'
  }

  let { label, value, display, tone = 'default' }: Props = $props()

  const pct = $derived(Math.min(100, Math.max(0, Number.isFinite(value) ? value : 0)))
  const shown = $derived(display ?? `${Math.round(pct)}%`)
</script>

<div class={['gauge', tone !== 'default' && tone]}>
  <div class="gauge-stage">
    <svg class="gauge-svg" viewBox="0 0 160 100" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(pct)}>
      <path
        class="gauge-track"
        d="M 16 88 A 64 64 0 0 1 144 88"
        fill="none"
        stroke-width="6"
        pathLength="100"
      />
      <path
        class="gauge-arc"
        d="M 16 88 A 64 64 0 0 1 144 88"
        fill="none"
        stroke-width="6"
        pathLength="100"
        stroke-dasharray="{pct} 100"
      />
    </svg>
    <div class="gauge-readout">
      <div class="gauge-display mono">{shown}</div>
    </div>
  </div>
  <div class="gauge-label">{label}</div>
</div>

<style>
  .gauge {
    min-width: 0;
    padding: 0.85rem 0.75rem 0.7rem;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .gauge-stage {
    position: relative;
    width: 100%;
    max-width: 11rem;
  }

  .gauge-svg {
    display: block;
    width: 100%;
    height: auto;
  }

  .gauge-track {
    stroke: var(--line);
  }

  .gauge-arc {
    stroke: var(--accent);
    transition: stroke-dasharray var(--dur) ease;
  }

  .ok .gauge-arc,
  .ok .gauge-display {
    stroke: var(--ok);
    color: var(--ok);
  }

  .warn .gauge-arc,
  .warn .gauge-display {
    stroke: var(--warn);
    color: var(--warn);
  }

  .bad .gauge-arc,
  .bad .gauge-display {
    stroke: var(--bad);
    color: var(--bad);
  }

  .gauge-readout {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0.1rem;
    text-align: center;
    pointer-events: none;
  }

  .gauge-display {
    font-size: 1.25rem;
    font-weight: 500;
    letter-spacing: -0.03em;
    color: var(--fg);
  }

  .gauge-label {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--code);
    margin-top: 0.15rem;
    text-align: center;
  }

  @media (prefers-reduced-motion: reduce) {
    .gauge-arc {
      transition: none;
    }
  }
</style>
