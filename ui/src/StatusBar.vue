<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { Terminal, PanelLeftClose, PanelLeftOpen, LogOut, Check, Loader2 } from '@lucide/vue'
import { logOpen, progress, sidebarMini, toggleSidebar } from './store'

const runCount = computed(() => Object.keys(progress.value).length)
const running = computed(() => runCount.value > 0)
const toggleLog = () => (logOpen.value = !logOpen.value)

// Login GitHub: menaikkan limit API GitHub (cek versi & update tool) dari 60 -> 5000/jam.
const account = ref<string | null>(null)
const menu = ref(false)
const token = ref('')
const busy = ref(false)
const error = ref('')
onMounted(async () => { account.value = await invoke<string | null>('github_status').catch(() => null) })
async function signIn() {
  busy.value = true
  error.value = ''
  try {
    account.value = await invoke<string>('github_sign_in', { token: token.value.trim() })
    token.value = ''
    menu.value = false
  } catch (e) {
    error.value = String(e)
  } finally {
    busy.value = false
  }
}
async function signOut() {
  await invoke('github_sign_out').catch(() => {})
  account.value = null
  menu.value = false
}
</script>

<template>
  <footer class="flex h-7 shrink-0 select-none items-center gap-0.5 border-t bg-card px-1 text-xs text-muted-foreground">
    <!-- Perkecil/lebarkan sidebar -->
    <button class="grid h-7 w-8 place-items-center rounded hover:bg-muted hover:text-foreground"
      :title="sidebarMini ? 'Lebarkan menu' : 'Perkecil menu'" @click="toggleSidebar">
      <PanelLeftOpen v-if="sidebarMini" class="size-4" /><PanelLeftClose v-else class="size-4" />
    </button>

    <!-- Status pemindaian -->
    <span class="ml-1.5 flex items-center gap-1.5">
      <span class="size-1.5 rounded-full" :class="running ? 'animate-pulse bg-primary' : 'bg-green-500'" />
      {{ running ? `Memindai ${runCount} target` : 'Siap' }}
    </span>

    <span class="ml-auto" />

    <!-- Login GitHub (popover membuka ke atas) -->
    <div class="relative">
      <button class="flex h-7 items-center gap-1.5 rounded px-2 hover:bg-muted hover:text-foreground" :class="account && 'text-foreground'"
        :title="account ? `GitHub: ${account}` : 'Login GitHub'" @click="menu = !menu">
        <svg viewBox="0 0 24 24" class="size-4 shrink-0" fill="currentColor" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.5.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.56 9.56 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 22 12c0-5.52-4.48-10-10-10z"/></svg>
        <span v-if="account" class="max-w-[9rem] truncate font-medium">{{ account }}</span>
      </button>
      <div v-if="menu" class="fixed inset-0 z-40" @click="menu = false" />
      <div v-if="menu" class="absolute right-0 bottom-full z-50 mb-1.5 w-72 rounded-xl border bg-popover p-3 text-sm text-popover-foreground shadow-lg">
        <template v-if="account">
          <div class="flex items-center gap-2 font-medium"><Check class="size-4 text-green-500" /> Masuk sebagai {{ account }}</div>
          <p class="mt-1 text-xs text-muted-foreground">Limit API GitHub naik ke 5000/jam untuk cek versi dan update tool.</p>
          <button class="mt-3 flex w-full items-center justify-center gap-1.5 rounded-md border py-1.5 text-xs font-medium transition-colors hover:bg-muted" @click="signOut">
            <LogOut class="size-3.5" /> Keluar
          </button>
        </template>
        <template v-else>
          <div class="flex items-center gap-2 font-medium">
            <svg viewBox="0 0 24 24" class="size-4" fill="currentColor" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.5.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.56 9.56 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 22 12c0-5.52-4.48-10-10-10z"/></svg>
            Login GitHub
          </div>
          <p class="mt-1 text-xs text-muted-foreground">Tempel Personal Access Token untuk menaikkan limit update tool dari 60 → 5000 permintaan/jam.</p>
          <input v-model="token" type="password" placeholder="ghp_… atau github_pat_…" autocomplete="off" spellcheck="false"
            class="mt-2 h-8 w-full rounded-md border bg-background px-2.5 text-xs outline-none transition-colors focus:border-ring" @keyup.enter="signIn" />
          <p v-if="error" class="mt-1 text-xs break-words text-destructive">{{ error }}</p>
          <button :disabled="busy || !token.trim()" class="mt-2 flex w-full items-center justify-center gap-1.5 rounded-md bg-primary py-1.5 text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50" @click="signIn">
            <Loader2 v-if="busy" class="size-3.5 animate-spin" /> Masuk
          </button>
          <p class="mt-2 text-[11px] text-muted-foreground">Buat token (classic, tanpa scope): <span class="font-mono">github.com/settings/tokens</span></p>
        </template>
      </div>
    </div>

    <!-- Panel log -->
    <button class="relative grid h-7 w-8 place-items-center rounded hover:bg-muted hover:text-foreground" :class="logOpen && 'text-foreground'"
      :title="logOpen ? 'Tutup panel log' : 'Buka panel log'" @click="toggleLog">
      <Terminal class="size-4" />
      <span v-if="running" class="absolute top-1 right-1.5 size-1.5 animate-pulse rounded-full bg-primary" />
    </button>
  </footer>
</template>
