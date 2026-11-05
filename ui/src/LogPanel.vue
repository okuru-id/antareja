<script setup lang="ts">
import { ref, watch, nextTick, computed } from 'vue'
import { useResizeObserver } from '@vueuse/core'
import { Terminal, Loader2, X, ChevronLeft, ChevronRight } from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { logOpen, logs, logTab, progress, tab } from './store'

const box = ref<HTMLElement>()
const ids = computed(() => Object.keys(logs.value))
// Tab aktif hilang (ditutup) -> pakai tab terakhir.
const active = computed(() => (logTab.value in logs.value ? logTab.value : ids.value.at(-1) ?? ''))
const lines = computed(() => logs.value[active.value]?.lines ?? [])
const running = computed(() => active.value in progress.value)
const pick = (id: string) => (logTab.value = id)
const drop = (id: string) => delete logs.value[id]
const showFindings = () => (tab.value = 'findings')
const close = () => (logOpen.value = false)
// Lebar panel: geser tepi kiri; disimpan per perangkat.
const width = ref(Number(localStorage.getItem('logWidth')) || 320)
function resize(e: PointerEvent) {
  const el = e.currentTarget as HTMLElement
  el.setPointerCapture(e.pointerId)
  const move = (m: PointerEvent) => (width.value = Math.min(Math.max(window.innerWidth - m.clientX, 220), window.innerWidth * 0.7))
  el.addEventListener('pointermove', move)
  el.addEventListener('pointerup', () => {
    el.removeEventListener('pointermove', move)
    localStorage.setItem('logWidth', String(Math.round(width.value)))
  }, { once: true })
}
// Strip tab tanpa scrollbar: tombol ‹ › muncul hanya bila ada tab tersembunyi di sisi itu.
const strip = ref<HTMLElement>()
const canLeft = ref(false)
const canRight = ref(false)
function sync() {
  const el = strip.value
  if (!el) return
  canLeft.value = el.scrollLeft > 10
  canRight.value = el.scrollLeft + el.clientWidth < el.scrollWidth - 10
}
function slide(dir: number) {
  const el = strip.value
  if (!el) return
  el.scrollLeft += dir * el.clientWidth * 0.7
  sync()
}
useResizeObserver(strip, sync)
// Tab aktif selalu terlihat (mis. scan baru dimulai).
watch([active, () => ids.value.length], () => nextTick(() => {
  // Geser strip saja (scrollIntoView juga menggeser dokumen di WebKitGTK).
  const el = strip.value, t = el?.querySelector<HTMLElement>('[data-active=true]')
  if (el && t) {
    if (t.offsetLeft < el.scrollLeft) el.scrollLeft = t.offsetLeft - 8
    else if (t.offsetLeft + t.offsetWidth > el.scrollLeft + el.clientWidth) el.scrollLeft = t.offsetLeft + t.offsetWidth - el.clientWidth + 8
  }
  sync()
}))

watch(() => [active.value, lines.value.length], () => nextTick(() => box.value?.scrollTo({ top: box.value.scrollHeight })))
</script>

<template>
  <aside class="relative flex shrink-0 flex-col border-l bg-card print:hidden" :style="{ width: width + 'px' }">
    <div class="absolute inset-y-0 -left-1 z-10 w-2 cursor-col-resize hover:bg-ring/40 active:bg-ring/60" title="Geser untuk ubah lebar" @pointerdown.prevent="resize" />
    <div class="flex h-11 items-center gap-2 border-b px-3 text-sm font-medium">
      <Terminal class="size-4 text-muted-foreground" /> Log scan
      <Loader2 v-if="running" class="size-3.5 animate-spin text-muted-foreground" />
      <Button v-if="!running && lines.length && !active.startsWith('update-')" variant="link" size="sm" class="ml-auto h-auto p-0" @click="showFindings">Lihat temuan</Button>
      <Button variant="ghost" size="icon-sm" title="Tutup panel" :class="(running || !lines.length || active.startsWith('update-')) && 'ml-auto'" @click="close"><X /></Button>
    </div>
    <div v-if="ids.length > 1" class="flex shrink-0 items-center border-b">
      <button v-if="canLeft" class="grid h-9 w-7 shrink-0 place-items-center text-muted-foreground hover:bg-muted hover:text-foreground" title="Tab sebelumnya" @click="slide(-1)">
        <ChevronLeft class="size-4" />
      </button>
      <div ref="strip" class="relative flex min-w-0 flex-1 gap-1 overflow-x-auto px-2 py-1.5 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden" @scroll="sync">
      <div v-for="id in ids" :key="id" :data-active="id === active" class="flex max-w-40 shrink-0 cursor-pointer items-center gap-1 rounded-md px-2 py-1 text-xs"
        :class="id === active ? 'bg-muted font-medium' : 'text-muted-foreground hover:bg-muted/50'" :title="logs[id]!.label" @click="pick(id)">
        <Loader2 v-if="id in progress" class="size-3 shrink-0 animate-spin" />
        <span class="truncate">{{ logs[id]!.label }}</span>
        <X v-if="!(id in progress)" class="size-3 shrink-0 opacity-60 hover:opacity-100" title="Tutup log" @click.stop="drop(id)" />
      </div>
      </div>
      <button v-if="canRight" class="grid h-9 w-7 shrink-0 place-items-center text-muted-foreground hover:bg-muted hover:text-foreground" title="Tab berikutnya" @click="slide(1)">
        <ChevronRight class="size-4" />
      </button>
    </div>
    <div ref="box" class="min-h-0 flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed">
      <p v-if="!lines.length" class="text-muted-foreground">Belum ada scan.</p>
      <!-- Sub-log (output tool / item per modul) diawali spasi setelah jam -->
      <p v-for="(l, i) in lines" :key="i" class="break-words" :class="/^\S+ {3}/.test(l) && 'pl-4 text-muted-foreground'">{{ l }}</p>
    </div>
  </aside>
</template>
