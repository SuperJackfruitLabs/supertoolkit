<script lang="ts">
  import Screen from '$lib/Screen.svelte';
  import { api, type Service } from '$lib/api';
  import '$lib/shared.css';

  let busy = $state('');
  async function revoke(name: string) {
    busy = name;
    try {
      await api.revoke(name);
      location.reload();
    } finally {
      busy = '';
    }
  }
</script>

<Screen
  title="Services"
  sub="What is connected, and — the column that matters — whether a long-lived secret ever reaches the wire."
  load={api.services}
>
  {#snippet children(d: { services: Service[] })}
    <table class="stk-table">
      <thead>
        <tr><th>Service</th><th>Operation</th><th>What goes on the wire</th><th>Held</th><th></th></tr>
      </thead>
      <tbody>
        {#each d.services as s}
          <tr>
            <td>
              <span class="light {s.connected ? 'ok' : 'off'}"></span><b>{s.name}</b>
              <div class="wire">{s.host}{s.kind === 'fronted server' ? ' · fronted server' : ''}</div>
            </td>
            <td><span class="pill quiet">{s.operation}</span></td>
            <td>
              <span class="pill {s.long_lived_on_the_wire ? 'approval' : 'agent'}">
                {s.long_lived_on_the_wire ? 'the token itself' : 'a derived credential'}
              </span>
              <div class="wire">{s.on_the_wire}</div>
            </td>
            <td class="mono">{s.fields.length ? s.fields.join(', ') : '—'}</td>
            <td>
              {#if s.connected}
                <button class="stk-btn sm" disabled={busy === s.name} onclick={() => revoke(s.name)}>
                  {busy === s.name ? 'Revoking…' : 'Revoke'}
                </button>
              {:else}
                <span class="note mono">stk connect {s.name}</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="note">
      A fronted server is one we did not write. It runs as a child holding only a placeholder,
      so if it is compromised what it holds is worthless off this machine.
    </p>
  {/snippet}
</Screen>
