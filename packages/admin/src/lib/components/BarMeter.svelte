<script lang="ts">
  interface Props {
    label: string
    value: number
    max?: number
    display?: string
    tone?: string
  }

  let { label, value, max, display, tone = 'default' }: Props = $props()

  const hasScale = $derived(max != null && max > 0)
  const ratio = $derived.by(() => {
    const n = Number.isFinite(value) ? value : 0
    if (hasScale) return Math.min(100, Math.max(0, (n / (max as number)) * 100))
    return n > 0 ? 100 : 0
  })
  const shown = $derived(display ?? String(value))
  const toneClass = $derived(tone === 'ok' || tone === 'warn' || tone === 'bad' ? tone : 'default')
</script>

<div class={['meter', toneClass, !hasScale && 'meter-bare']}>
  <div class="meter-head">
    <span class="meter-label">{label}</span>
    <span class="meter-value mono">{shown}</span>
  </div>
  <div
    class="meter-track"
    role={hasScale ? 'meter' : undefined}
    aria-label={label}
    aria-valuemin={hasScale ? 0 : undefined}
    aria-valuemax={hasScale ? max : undefined}
    aria-valuenow={hasScale ? value : undefined}
  >
    <div class="meter-fill" style:width="{ratio}%"></div>
  </div>
</div>

<style>
  .meter {
    min-width: 0;
    padding: 0.85rem 1.1rem;
  }

  .meter-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.5rem;
    margin-bottom: 0.45rem;
  }

  .meter-label {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--code);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .meter-value {
    font-size: 0.95rem;
    color: var(--fg);
    flex-shrink: 0;
  }

  .meter-track {
    height: 4px;
    background: var(--line);
    overflow: hidden;
  }

  .meter-bare .meter-track {
    height: 2px;
  }

  .meter-fill {
    height: 100%;
    background: var(--accent);
    transition: width var(--dur) ease;
  }

  .meter-bare .meter-fill {
    opacity: 0.45;
  }

  .ok .meter-fill {
    background: var(--ok);
  }

  .warn .meter-fill {
    background: var(--warn);
  }

  .bad .meter-fill {
    background: var(--bad);
  }

  .ok .meter-value {
    color: var(--ok);
  }

  .warn .meter-value {
    color: var(--warn);
  }

  .bad .meter-value {
    color: var(--bad);
  }

  @media (prefers-reduced-motion: reduce) {
    .meter-fill {
      transition: none;
    }
  }
</style>
