<script lang="ts">
  import '../app.css';
  import { VibeRoot } from '@superjackfruit/vibekit';
  import { page } from '$app/state';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';

  let { children } = $props();

  // A vibe is the person's choice across the whole suite, not a property of
  // this product. Studio is only the default.
  const VIBES = ['daylight', 'paper', 'studio', 'quiet'] as const;
  let vibe = $state<(typeof VIBES)[number]>('studio');
  let theme = $state<'light' | 'dark'>('light');
  let pending = $state(0);

  const SECTIONS = [
    { href: '/', label: 'Status' },
    { href: '/services', label: 'Services' },
    { href: '/policy', label: 'Policy' },
    { href: '/approvals', label: 'Approvals' },
    { href: '/audit', label: 'Audit' },
  ];

  onMount(() => {
    try {
      const saved = localStorage.getItem('stk.vibe');
      if (saved && (VIBES as readonly string[]).includes(saved)) vibe = saved as typeof vibe;
      const savedTheme = localStorage.getItem('stk.theme');
      if (savedTheme === 'dark' || savedTheme === 'light') theme = savedTheme;
    } catch {
      // Private browsing, or storage refused. The defaults are fine.
    }
    const tick = async () => {
      try {
        pending = (await api.status()).pending;
      } catch {
        // The status strip is not worth breaking a page over.
      }
    };
    tick();
    const t = setInterval(tick, 5000);
    return () => clearInterval(t);
  });

  // VibeRoot puts the vibe and theme on <html>; this only remembers the choice.
  $effect(() => {
    try {
      localStorage.setItem('stk.vibe', vibe);
      localStorage.setItem('stk.theme', theme);
    } catch {
      // Private browsing, or storage refused. Not worth failing a render over.
    }
  });
</script>

<VibeRoot {vibe} {theme}>
<div class="shell">
  <header class="top">
    <span class="mark">supertoolkit<span class="dim"> / stk</span></span>
    <nav class="tabs" aria-label="Sections">
      {#each SECTIONS as s}
        <a
          class="tab"
          href={s.href}
          aria-current={page.url.pathname === s.href ? 'page' : undefined}
        >
          {s.label}{#if s.label === 'Approvals' && pending}<span class="n">{pending}</span>{/if}
        </a>
      {/each}
    </nav>
    <span class="spacer"></span>
    <label class="pick">
      <span class="sr">Vibe</span>
      <select bind:value={vibe}>
        {#each VIBES as v}<option value={v}>{v}</option>{/each}
      </select>
    </label>
    <button class="btn sm" onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')}>
      {theme === 'dark' ? 'Light' : 'Dark'}
    </button>
  </header>
  <main>{@render children()}</main>
</div>
</VibeRoot>

<style>
  .shell { min-height: 100vh; display: grid; grid-template-rows: auto 1fr; }
  .top {
    display: flex; align-items: center; gap: 16px; padding: 14px 24px;
    border-bottom: 1px solid var(--vk-color-line); background: var(--vk-color-raised);
  }
  .mark { font-family: var(--vk-font-mono); font-size: 13px; font-weight: 600; letter-spacing: 0.06em; }
  .dim { color: var(--vk-color-faint); }
  .tabs { display: flex; gap: 2px; margin-left: 8px; }
  .tab {
    font-size: 13px; padding: 6px 12px; border: 1px solid transparent; border-radius: 4px;
    color: var(--vk-color-muted); text-decoration: none;
  }
  .tab[aria-current='page'] {
    background: var(--vk-color-surface); border-color: var(--vk-color-line);
    color: var(--vk-color-text); font-weight: 600;
  }
  .n { font-family: var(--vk-font-mono); font-size: 11px; color: var(--vk-color-signal-text); margin-left: 6px; }
  .spacer { flex: 1; }
  .pick select, .btn {
    font-family: var(--vk-font-body); font-size: 12px; padding: 5px 10px;
    border: 1px solid var(--vk-color-line); background: var(--vk-color-raised);
    color: var(--vk-color-text); cursor: pointer;
  }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  main { padding: 24px; display: grid; gap: 20px; align-content: start; }
</style>
