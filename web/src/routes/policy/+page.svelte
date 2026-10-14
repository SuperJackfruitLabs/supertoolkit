<script lang="ts">
  import Screen from '$lib/Screen.svelte';
  import { api, type PolicyRow } from '$lib/api';
  import '$lib/shared.css';

  const CHOICES = ['agent', 'approval', 'deny'] as const;
  let error = $state('');

  // A capability that changes the world cannot be promoted to agent from here.
  // The broker refuses it too; this only stops the control being offered.
  const allowed = (row: PolicyRow, c: string) => c !== 'agent' || row.ceiling === 'agent';

  async function set(row: PolicyRow, choice: string) {
    error = '';
    try {
      await api.setPolicy(row.category, row.action, choice);
      row.policy = choice as PolicyRow['policy'];
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }
</script>

<Screen
  title="Policy"
  sub="Who may trigger what. Governs triggering only, never who holds the credential. Reads default to agent; anything that changes the world defaults to approval."
  load={api.policy}
>
  {#snippet children(d: { rows: PolicyRow[] })}
    {#if error}<div class="err">{error}</div>{/if}
    <table class="stk-table">
      <thead>
        <tr><th>Action</th>{#each CHOICES as c}<th class="pick">{c}</th>{/each}<th>Note</th></tr>
      </thead>
      <tbody>
        {#each d.rows as row (row.category + row.action)}
          <tr>
            <td><span class="mono">{row.category} / {row.action}</span></td>
            {#each CHOICES as c}
              <td class="pick">
                <input
                  type="radio"
                  name={row.category + row.action}
                  checked={row.policy === c}
                  disabled={!allowed(row, c)}
                  aria-label="{row.action}: {c}"
                  onchange={() => set(row, c)}
                />
              </td>
            {/each}
            <td class="note">
              {row.summary}
              {#if row.ceiling !== 'agent'}<span class="wire"> · approval is its ceiling</span>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <div class="inv">
      <b>A profile narrows; it never widens.</b>
      <span>This page is the ceiling. A profile selects a subset of it, so a mistake there can only ever grant less than you intended.</span>
    </div>
  {/snippet}
</Screen>

<style>
  .pick { text-align: center; width: 92px; }
  .err {
    padding: 10px 14px; border-left: 3px solid var(--vk-color-signal);
    background: var(--vk-color-signal-wash); font-size: 13px;
  }
</style>
