<script setup lang="ts">
// Kontrol window custom (decorations: false). Titik perhatian cross-platform: macOS/Windows perlu penyesuaian.
import { getCurrentWindow } from '@tauri-apps/api/window'
import { Minus, Square, X, Sun, Moon } from '@lucide/vue'
import { dark, toggleTheme } from './store'
import antarejaLogo from './assets/antareja.svg'
defineProps<{ title: string; sub: string }>()
const win = getCurrentWindow()
</script>

<template>
  <header data-tauri-drag-region class="flex h-9 shrink-0 select-none items-center border-b bg-card">
    <div data-tauri-drag-region class="flex min-w-0 flex-1 items-center gap-2 pl-3 text-sm">
      <img :src="antarejaLogo" alt="" class="pointer-events-none size-4 shrink-0" />
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
