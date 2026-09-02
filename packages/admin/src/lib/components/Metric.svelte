<script lang="ts">
  interface Props {
    label: string
    value: string
    tone?: 'default' | 'ok' | 'bad'
    note?: string
  }

  let { label, value, tone = 'default', note }: Props = $props()
</script>

<div class="metric">
  <div class="metric-label">{label}</div>
  <div class="metric-value" class:ok={tone === 'ok'} class:bad={tone === 'bad'}>{value}</div>
  {#if note}
    <div class="metric-note">{note}</div>
  {/if}
</div>
