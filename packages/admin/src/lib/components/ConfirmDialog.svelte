<script lang="ts">
  interface Props {
    open: boolean
    title: string
    message: string
    confirmLabel?: string
    danger?: boolean
    onconfirm: () => void
    oncancel: () => void
  }

  let { open, title, message, confirmLabel = 'Confirm', danger = false, onconfirm, oncancel }: Props = $props()

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') oncancel()
  }
</script>

<svelte:window onkeydown={open ? handleKeydown : undefined} />

{#if open}
  <div class="dialog-overlay" role="presentation" onclick={oncancel}>
    <div
      class="dialog"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <div class="dialog-title" id="confirm-dialog-title">{title}</div>
      <p class="dialog-body">{message}</p>
      <div class="dialog-actions">
        <button type="button" class="btn btn-sm" onclick={oncancel}>Cancel</button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-danger={danger}
          class:btn-primary={!danger}
          onclick={onconfirm}
        >
          {confirmLabel}
        </button>
      </div>
    </div>
  </div>
{/if}
