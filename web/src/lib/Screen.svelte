<script lang="ts">
  // Every screen loads, fails or shows. Doing it in one place means a screen
  // cannot forget the failure case — which on a page about credentials would
  // otherwise read as "nothing is configured".
  let { title, sub, load, children } = $props<{
    title: string;
    sub: string;
    load: () => Promise<unknown>;
    children: import('svelte').Snippet<[any]>;
  }>();

  let state = $state<{ status: 'loading' | 'ok' | 'failed'; data?: any; error?: string }>({
    status: 'loading',
  });

  async function run() {
    state = { status: 'loading' };
    try {
      state = { status: 'ok', data: await load() };
    } catch (e) {
      state = { status: 'failed', error: e instanceof Error ? e.message : String(e) };
    }
  }
  $effect(() => {
    run();
  });
</script>

<div>
  <h1>{title}</h1>
  <p class="sub">{sub}</p>
</div>

{#if state.status === 'loading'}
  <p class="note">Loading…</p>
{:else if state.status === 'failed'}
  <div class="failed">
    <b>Could not read this.</b>
    <span>{state.error}</span>
    <button class="btn" onclick={run}>Try again</button>
  </div>
{:else}
  {@render children(state.data)}
{/if}

<style>
  h1 { font-family: var(--vk-font-display); font-size: 21px; font-weight: 650; margin: 0; }
  .sub { font-size: 13.5px; color: var(--vk-color-muted); margin: 5px 0 0; max-width: 74ch; }
  .note { font-size: 13px; color: var(--vk-color-muted); }
  .failed {
    display: grid; gap: 8px; justify-items: start; padding: 14px 16px;
    border-left: 3px solid var(--vk-color-signal); background: var(--vk-color-signal-wash);
  }
  .failed span { font-size: 12.5px; color: var(--vk-color-muted); }
  .btn {
    font-family: var(--vk-font-body); font-size: 13px; padding: 6px 12px;
    border: 1px solid var(--vk-color-line); background: var(--vk-color-raised);
    color: var(--vk-color-text); cursor: pointer;
  }
</style>
