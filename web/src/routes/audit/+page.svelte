<script lang="ts">
  import Screen from '$lib/Screen.svelte';
  import { api, type AuditEffect } from '$lib/api';
  import '$lib/shared.css';

  let filter = $state('');
  const matches = (e: AuditEffect, q: string) =>
    !q ||
    [e.category, e.action, e.caller, e.outcome, e.policy].some((v) =>
      v?.toLowerCase().includes(q.toLowerCase()),
    );
  const time = (iso: string) => new Date(iso).toLocaleTimeString();
</script>

<Screen
  title="Audit"
  sub="Every effect, with the scope it used and who decided it. Fingerprints, never credentials — a test asserts this log cannot contain one."
  load={api.audit}
>
  {#snippet children(d: { effects: AuditEffect[] })}
    <div class="filters">
      <input bind:value={filter} type="search" placeholder="Filter by action, caller or outcome" aria-label="Filter" />
      <span class="note mono">{d.effects.filter((e) => matches(e, filter)).length} of {d.effects.length}</span>
    </div>
    <table class="stk-table">
      <thead>
        <tr><th class="num">Time</th><th>Action</th><th>Policy</th><th>Caller</th><th>Credential</th><th>Outcome</th></tr>
      </thead>
      <tbody>
        {#each d.effects.filter((e) => matches(e, filter)) as e}
          <tr>
            <td class="num mono">{time(e.when)}</td>
            <td class="mono">{e.category} / {e.action}</td>
            <td><span class="pill {e.policy}">{e.policy}</span></td>
            <td class="mono">{e.caller}</td>
            <td class="mono">{e.credential}</td>
            <td>{e.outcome}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if !d.effects.length}<p class="note">No effects recorded yet.</p>{/if}
  {/snippet}
</Screen>

<style>
  .filters { display: flex; gap: 8px; align-items: center; }
  .filters input {
    font-family: var(--vk-font-body); font-size: 13px; padding: 6px 10px; min-width: 260px;
    border: 1px solid var(--vk-color-line); background: var(--vk-color-raised); color: var(--vk-color-text);
  }
</style>
