<script setup lang="ts">
// Kontrol window custom (decorations: false). Titik perhatian cross-platform: macOS/Windows perlu penyesuaian.
import { getCurrentWindow } from '@tauri-apps/api/window'
import { Minus, Square, X, Sun, Moon } from '@lucide/vue'
import { dark, toggleTheme } from './store'
defineProps<{ title: string; sub: string }>()
const win = getCurrentWindow()
</script>

<template>
  <header data-tauri-drag-region class="flex h-9 shrink-0 select-none items-center border-b bg-card">
    <div data-tauri-drag-region class="flex min-w-0 flex-1 items-center gap-2 pl-3 text-sm">
      <svg viewBox="76 76 872 872" class="pointer-events-none size-4 shrink-0" aria-hidden="true">
        <path d="M512 104 L856 240 Q874 247 874 296 V540 Q874 706 682 826 L512 920 L342 826 Q150 706 150 540 V296 Q150 247 168 240 Z" fill="#2563eb"/>
        <g stroke="#bfdbfe" stroke-width="6" stroke-opacity="0.45">
          <circle cx="512" cy="500" r="258" fill="#16337a"/>
          <circle cx="512" cy="500" r="176" fill="#112a66"/>
          <circle cx="512" cy="500" r="92" fill="#0d2152"/>
        </g>
        <g stroke="#bfdbfe" stroke-width="6" stroke-opacity="0.28">
          <line x1="512" y1="242" x2="512" y2="758"/>
          <line x1="254" y1="500" x2="770" y2="500"/>
        </g>
        <path d="M512 500 L512 242 A258 258 0 0 1 710 334 Z" fill="#7dd3fc" fill-opacity="0.5"/>
        <line x1="512" y1="500" x2="512" y2="242" stroke="#e0f2fe" stroke-width="13" stroke-linecap="round"/>
        <circle cx="616" cy="352" r="21" fill="#e0f2fe"/>
      </svg>
      <span class="pointer-events-none shrink-0 font-semibold tracking-tight">Antareja</span>
      <span class="pointer-events-none text-muted-foreground/60">/</span>
      <span class="pointer-events-none shrink-0 font-semibold">{{ title }}</span>
      <span class="pointer-events-none hidden truncate text-muted-foreground md:inline">· {{ sub }}</span>
    </div>
    <button class="grid h-9 w-10 place-items-center text-muted-foreground hover:bg-muted hover:text-foreground" :title="dark ? 'Tema terang' : 'Tema gelap'" @click="toggleTheme">
      <Sun v-if="dark" class="size-4" /><Moon v-else class="size-4" />
    </button>
    <span class="mx-1 h-4 w-px bg-border" />
    <button class="grid h-9 w-11 place-items-center hover:bg-muted" title="Minimize" @click="win.minimize()"><Minus class="size-4" /></button>
    <button class="grid h-9 w-11 place-items-center hover:bg-muted" title="Maximize" @click="win.toggleMaximize()"><Square class="size-3.5" /></button>
    <button class="grid h-9 w-11 place-items-center hover:bg-destructive hover:text-white" title="Close" @click="win.close()"><X class="size-4" /></button>
  </header>
</template>
