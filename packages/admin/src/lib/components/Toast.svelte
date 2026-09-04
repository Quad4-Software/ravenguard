<script lang="ts">
  import { toast, type ToastKind } from '$lib/toast.svelte'
  import { CheckCircle2, CircleAlert, Info, X } from '@lucide/svelte'

  function iconFor(kind: ToastKind) {
    if (kind === 'success') return CheckCircle2
    if (kind === 'warning' || kind === 'error') return CircleAlert
    return Info
  }
</script>

<div class="toast-stack" role="status" aria-live="polite" aria-relevant="additions">
  {#each toast.items as item (item.id)}
    {@const Icon = iconFor(item.kind)}
    <div class="toast toast-{item.kind}" data-kind={item.kind}>
      <Icon class="toast-icon" size={16} strokeWidth={1.75} aria-hidden="true" />
      <span class="toast-msg">{item.message}</span>
      <button
        type="button"
        class="toast-dismiss"
        aria-label="Dismiss"
        onclick={() => toast.dismiss(item.id)}
      >
        <X size={14} strokeWidth={2} aria-hidden="true" />
      </button>
    </div>
  {/each}
</div>
