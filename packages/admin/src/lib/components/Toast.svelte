<script lang="ts">
  import { toast } from '$lib/toast.svelte'
</script>

<div class="toast-stack" role="status" aria-live="polite">
  {#each toast.items as item (item.id)}
    <div class="toast" class:toast-error={item.kind === 'error'}>
      <span>{item.message}</span>
    </div>
  {/each}
</div>
