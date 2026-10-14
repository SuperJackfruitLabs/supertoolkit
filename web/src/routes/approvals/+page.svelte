<script lang="ts">
  import Screen from '$lib/Screen.svelte';
  import { api, type Effect } from '$lib/api';
  import '$lib/shared.css';

  let busy = $state('');
  let error = $state('');

  async function decide(e: Effect, allow: boolean) {
    busy = e.id;
    error = '';
    try {
      await api.decide(e.id, allow);
      location.reload();
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = '';
    }
  }

  const ago = (iso: string) => {
    const t = new Date(iso).getTime();
    // "NaNh ago" is what this printed when the field it reads was renamed. A
    // time we cannot read is worth saying plainly rather than rendering as
    // arithmetic on a missing value.
    if (!Number.isFinite(t)) return 'an unknown time';
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return `${Math.round(s)}s`;
    if (s < 5400) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
  };
</script>

<Screen
  title="Approvals"
  sub="Each shows the exact request that would be sent, not a summary. Approving a description is not approving the act."
  load={api.approvals}
>
  {#snippet children(d: { effects: Effect[] })}
    {#if error}<div class="err">{error}</div>{/if}
    {#if !d.effects.length}
      <p class="note">Nothing is waiting on you.</p>
    {/if}
    {#each d.effects as e (e.id)}
      <div class="eff">
        <div class="eff-h">
          <span class="light {e.state === 'pending' ? 'warn' : 'off'}"></span>
          <span class="who">{e.service} / {e.capability}</span>
          <span class="pill {e.state === 'pending' ? 'approval' : 'deny'}">{e.state}</span>
          <span class="spacer"></span>
          <span class="age">
            {#if e.state === 'pending'}waiting {ago(e.submitted)}{:else}{e.state} · {ago(e.submitted)} ago{/if}
          </span>
        </div>
        <div class="eff-b">
          <div class="exact">{e.summary}</div>
          {#if e.args && Object.keys(e.args).length}
            <dl>
              {#each Object.entries(e.args) as [k, v]}
                <dt>{k}</dt><dd class="mono">{v}</dd>
              {/each}
            </dl>
          {/if}
          {#if e.state === 'expired'}
            <p class="note">Nobody decided in time, so nothing happened. Expiry is never approval.</p>
          {/if}
        </div>
        {#if e.state === 'pending'}
          <div class="eff-f">
            <button class="stk-btn primary" disabled={busy === e.id} onclick={() => decide(e, true)}>Approve</button>
            <button class="stk-btn danger" disabled={busy === e.id} onclick={() => decide(e, false)}>Refuse</button>
            <span class="spacer"></span>
            <span class="note mono">id {e.id}</span>
          </div>
        {/if}
      </div>
    {/each}
  {/snippet}
</Screen>

<style>
  .eff { border: 1px solid var(--vk-color-line); background: var(--vk-color-raised); }
  .eff-h {
    display: flex; align-items: center; gap: 12px; padding: 12px 16px;
    border-bottom: 1px solid var(--vk-color-line); background: var(--vk-color-surface);
  }
  .who { font-family: var(--vk-font-mono); font-size: 12.5px; font-weight: 600; }
  .age { font-family: var(--vk-font-mono); font-size: 11.5px; color: var(--vk-color-faint); }
  .spacer { flex: 1; }
  .eff-b { padding: 14px 16px; display: grid; gap: 10px; }
  .exact {
    font-family: var(--vk-font-mono); font-size: 12.5px; background: var(--vk-color-bg);
    border: 1px solid var(--vk-color-line); padding: 10px 12px; white-space: pre-wrap;
  }
  .eff-f { display: flex; gap: 8px; padding: 12px 16px; border-top: 1px solid var(--vk-color-line); align-items: center; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; font-size: 12.5px; }
  dt { font-family: var(--vk-font-mono); font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--vk-color-faint); }
  dd { margin: 0; }
  .err { padding: 10px 14px; border-left: 3px solid var(--vk-color-signal); background: var(--vk-color-signal-wash); font-size: 13px; }
</style>
