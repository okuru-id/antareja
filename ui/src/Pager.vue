<script setup lang="ts">
import { computed, watch } from 'vue'
import { ChevronLeft, ChevronRight } from '@lucide/vue'
import { Button } from '@/components/ui/button'

const props = defineProps<{ total: number; per: number }>()
const page = defineModel<number>({ required: true })
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.per)))
const from = computed(() => (props.total ? (page.value - 1) * props.per + 1 : 0))
const to = computed(() => Math.min(page.value * props.per, props.total))

// Jaga halaman tetap dalam rentang (mis. setelah filter mengecilkan data).
watch([pages, () => props.total], () => {
  if (page.value > pages.value) page.value = pages.value
  if (page.value < 1) page.value = 1
})

// Daftar tombol ringkas: 1 … c-1 c c+1 … n (maks beberapa tombol, bukan semua halaman).
const items = computed<(number | '…')[]>(() => {
  const n = pages.value
  const c = page.value
  if (n <= 7) return Array.from({ length: n }, (_, i) => i + 1)
  const keep = new Set([1, n, c, c - 1, c + 1])
  if (c <= 3) [2, 3, 4].forEach((x) => keep.add(x))
  if (c >= n - 2) [n - 1, n - 2, n - 3].forEach((x) => keep.add(x))
  const nums = [...keep].filter((x) => x >= 1 && x <= n).sort((a, b) => a - b)
  const out: (number | '…')[] = []
  let prev = 0
  for (const x of nums) {
    if (x - prev > 1) out.push('…')
    out.push(x)
    prev = x
  }
  return out
})
</script>

<template>
  <div v-if="total > per" class="flex items-center gap-1 border-t px-4 py-2 text-xs text-muted-foreground">
    <span class="mr-auto tabular-nums">{{ from }}–{{ to }} dari {{ total }}</span>
    <Button variant="ghost" size="icon-sm" title="Sebelumnya" :disabled="page <= 1" @click="page--"><ChevronLeft /></Button>
    <template v-for="(it, i) in items" :key="i">
      <span v-if="it === '…'" class="grid size-7 place-items-center text-muted-foreground select-none">…</span>
      <Button v-else size="icon-sm" :variant="it === page ? 'secondary' : 'ghost'" class="tabular-nums" @click="page = it">{{ it }}</Button>
    </template>
    <Button variant="ghost" size="icon-sm" title="Berikutnya" :disabled="page >= pages" @click="page++"><ChevronRight /></Button>
  </div>
</template>
