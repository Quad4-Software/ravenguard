<script lang="ts" module>
  let fillSeq = 0
</script>

<script lang="ts">
  interface Props {
    values: number[]
    label?: string
    height?: number
    stroke?: string
    format?: (n: number) => string
    unit?: string
    fill?: boolean
  }

  let {
    values,
    label = '',
    height = 64,
    stroke = 'var(--accent)',
    format,
    unit = '',
    fill = true,
  }: Props = $props()

  const width = 240
  const pad = 6
  const fillId = `spark-fill-${++fillSeq}`

  const geom = $derived.by(() => {
    const empty = values.length === 0
    const pts = values.length === 1 ? [values[0], values[0]] : values
    const latest = values.length ? values[values.length - 1] : 0
    if (empty) {
      return { empty: true, line: '', area: '', latest, lastX: 0, lastY: 0, guides: [0.25, 0.5, 0.75] }
    }
    const max = Math.max(...pts, 1)
    const min = Math.min(...pts, 0)
    const span = Math.max(max - min, 1)
    const coords = pts.map((v, i) => {
      const x = pad + (i / Math.max(pts.length - 1, 1)) * (width - pad * 2)
      const y = height - pad - ((v - min) / span) * (height - pad * 2)
      return { x, y }
    })
    const line = coords
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
      .join(' ')
    const first = coords[0]
    const last = coords[coords.length - 1]
    const area = `${line} L${last.x.toFixed(1)} ${(height - pad).toFixed(1)} L${first.x.toFixed(1)} ${(height - pad).toFixed(1)} Z`
    return {
      empty: false,
      line,
      area,
      latest,
      lastX: last.x,
      lastY: last.y,
      guides: [0.25, 0.5, 0.75],
    }
  })

  const shown = $derived.by(() => {
    if (geom.empty) return '-'
    if (format) return format(geom.latest)
    if (unit) return `${geom.latest} ${unit}`
    if (Number.isInteger(geom.latest)) return String(geom.latest)
    return geom.latest.toFixed(1)
  })
</script>

<div class="spark" style:--spark={stroke}>
  <div class="spark-head">
    {#if label}
      <span class="spark-label">{label}</span>
    {/if}
    <span class="spark-value mono">{shown}</span>
  </div>
  <svg class="spark-svg" viewBox="0 0 {width} {height}" role="img" aria-label={label || 'chart'}>
    <defs>
      <linearGradient id={fillId} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color={stroke} stop-opacity="0.28" />
        <stop offset="100%" stop-color={stroke} stop-opacity="0.02" />
      </linearGradient>
    </defs>
    {#each geom.guides as t (t)}
      <line
        x1={pad}
        y1={pad + t * (height - pad * 2)}
        x2={width - pad}
        y2={pad + t * (height - pad * 2)}
        stroke="var(--line)"
        stroke-width="1"
        vector-effect="non-scaling-stroke"
      />
    {/each}
    {#if geom.empty}
      <line
        x1={pad}
        y1={height / 2}
        x2={width - pad}
        y2={height / 2}
        stroke="var(--line)"
        stroke-width="1"
        vector-effect="non-scaling-stroke"
      />
    {:else}
      {#if fill}
        <path d={geom.area} fill="url(#{fillId})" stroke="none" />
      {/if}
      <path
        d={geom.line}
        fill="none"
        stroke={stroke}
        stroke-width="1.5"
        vector-effect="non-scaling-stroke"
      />
      <circle cx={geom.lastX} cy={geom.lastY} r="2.2" fill={stroke} />
    {/if}
  </svg>
  {#if geom.empty}
    <div class="spark-empty">no samples</div>
  {/if}
</div>

<style>
  .spark {
    border: 1px solid var(--line);
    padding: 0.75rem 0.85rem 0.5rem;
    min-width: 0;
    overflow: hidden;
  }

  .spark-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }

  .spark-label {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--code);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .spark-value {
    font-size: 0.95rem;
    color: var(--spark, var(--fg));
    flex-shrink: 0;
    margin-left: auto;
  }

  .spark-svg {
    display: block;
    width: 100%;
    height: auto;
  }

  .spark-empty {
    font-family: var(--font-mono);
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--code);
    margin-top: 0.35rem;
  }
</style>
