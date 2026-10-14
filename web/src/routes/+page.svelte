<script lang="ts">
  import Screen from '$lib/Screen.svelte';
  import { api, type Status } from '$lib/api';
  import '$lib/shared.css';
</script>

<Screen
  title="Status"
  sub="What stk doctor reports, continuously. The last row is the promise, checked rather than claimed."
  load={api.status}
>
  {#snippet children(s: Status)}
    <div class="inv">
      <b>The agent never holds a credential.</b>
      <span>Not configurable. Everything else on these screens is policy you set.</span>
    </div>

    <div class="tiles">
      <div class="tile"><div class="k">Workspace</div><div class="v mono">{s.workspace}</div></div>
      <div class="tile"><div class="k">Services</div><div class="v">{s.services}</div><div class="n">{s.servers} fronted server(s)</div></div>
      <div class="tile"><div class="k">Profiles</div><div class="v">{s.profiles.length || 1}</div><div class="n">{s.profiles.length ? s.profiles.join(', ') : 'default only'}</div></div>
      <div class="tile"><div class="k">Waiting on you</div><div class="v">{s.pending}</div></div>
    </div>

    <table class="stk-table">
      <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>
        {#each s.checks as c}
          <tr>
            <td><span class="light {c.state}"></span>{c.label}</td>
            <td><span class="pill {c.state === 'ok' ? 'agent' : c.state === 'warn' ? 'approval' : 'deny'}">{c.state}</span></td>
            <td class="note">{c.detail}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/snippet}
</Screen>

<style>
  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .tile { border: 1px solid var(--vk-color-line); background: var(--vk-color-raised); padding: 14px 16px; }
  .k { font-family: var(--vk-font-mono); font-size: 10.5px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--vk-color-faint); }
  .v { font-size: 22px; font-weight: 650; margin-top: 6px; font-variant-numeric: tabular-nums; }
  .v.mono { font-family: var(--vk-font-mono); font-size: 15px; font-weight: 500; }
  .n { font-size: 12px; color: var(--vk-color-muted); margin-top: 4px; }
</style>
