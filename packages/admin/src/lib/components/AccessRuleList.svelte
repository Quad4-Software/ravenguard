<script lang="ts">
  import { emptyDraft, type DraftRule, type RuleType } from '$lib/access-rules'

  interface Props {
    rules?: DraftRule[]
    idPrefix: string
    keepHash?: boolean
  }

  let { rules = $bindable<DraftRule[]>([]), idPrefix, keepHash = false }: Props = $props()

  const types: RuleType[] = ['password', 'pin', 'ip_allowlist', 'header', 'user_agent']

  function addRule() {
    rules = [...rules, emptyDraft()]
  }

  function removeRule(index: number) {
    rules = rules.filter((_, i) => i !== index)
  }
</script>

{#each rules as rule, i (rule.id)}
  <fieldset class="rule-block">
    <legend>Rule {i + 1}</legend>
    <div class="field-row">
      <div class="field">
        <label for="{idPrefix}-{rule.id}-type">Rule type</label>
        <select id="{idPrefix}-{rule.id}-type" bind:value={rule.type}>
          {#each types as t (t)}
            <option value={t}>{t}</option>
          {/each}
        </select>
      </div>
      {#if rule.type === 'password' || rule.type === 'pin'}
        <div class="field">
          <label for="{idPrefix}-{rule.id}-secret">Secret</label>
          <input
            id="{idPrefix}-{rule.id}-secret"
            type="password"
            bind:value={rule.secret}
            required={!keepHash || !rule.secret_hash}
            placeholder={keepHash && rule.secret_hash ? 'leave blank to keep current' : ''}
            autocomplete="new-password"
          />
          {#if keepHash && rule.secret_hash}
            <p class="field-help">Leave blank to keep the current secret</p>
          {/if}
        </div>
      {:else if rule.type === 'ip_allowlist'}
        <div class="field">
          <label for="{idPrefix}-{rule.id}-cidrs">CIDRs</label>
          <textarea
            id="{idPrefix}-{rule.id}-cidrs"
            bind:value={rule.cidrs}
            placeholder="one CIDR per line"
            rows="3"
            required
          ></textarea>
        </div>
      {:else if rule.type === 'header'}
        <div class="field">
          <label for="{idPrefix}-{rule.id}-header-name">Header name</label>
          <input id="{idPrefix}-{rule.id}-header-name" type="text" bind:value={rule.header_name} required />
        </div>
        <div class="field">
          <label for="{idPrefix}-{rule.id}-header-value">Header value</label>
          <input id="{idPrefix}-{rule.id}-header-value" type="text" bind:value={rule.header_value} required />
        </div>
      {:else if rule.type === 'user_agent'}
        <div class="field">
          <label for="{idPrefix}-{rule.id}-ua">User agents</label>
          <textarea
            id="{idPrefix}-{rule.id}-ua"
            bind:value={rule.user_agents}
            placeholder="substring per line"
            rows="3"
            required
          ></textarea>
        </div>
      {/if}
      <div class="field-btn">
        <button type="button" class="btn btn-sm" onclick={() => removeRule(i)}>Remove</button>
      </div>
    </div>
  </fieldset>
{/each}

<div class="rule-actions">
  <button type="button" class="btn btn-sm" onclick={addRule}>Add rule</button>
</div>

<style>
  .rule-block {
    margin-bottom: 0.75rem;
  }

  .rule-actions {
    display: flex;
    gap: 0.6rem;
    margin-bottom: 1rem;
  }
</style>
