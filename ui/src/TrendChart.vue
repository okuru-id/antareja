<script setup lang="ts">
import { computed, useTemplateRef } from 'vue'
import { useElementSize } from '@vueuse/core'
import { SEVERITIES, SEV_COLOR, postureAt, endOfDay } from './store'

const props = defineProps<{ days: number }>()
// Lebar diukur dari elemen agar 1 unit viewBox = 1px: teks & garis tidak ikut membesar di layar lebar.
const box = useTemplateRef<HTMLElement>('box')
const { width } = useElementSize(box)
const W = computed(() => Math.max(240, Math.round(width.value)))
const H = 220, L = 34, B = 22 // area plot: x L..W, y 8..H-B

// series[i] = posture pada akhir hari ke-i (lama -> baru)
const points = computed(() => Array.from({ length: props.days }, (_, i) => postureAt(endOfDay(props.days - 1 - i))))
const max = computed(() => {
  const m = Math.max(4, ...points.value.flat())
  const step = 10 ** Math.floor(Math.log10(m)) // skala bulat: 1/2/5 x 10^n
  return Math.ceil(m / step) * step
})
const x = (i: number) => L + (i * (W.value - L - 8)) / Math.max(1, props.days - 1)
const y = (v: number) => 8 + (1 - v / max.value) * (H - B - 8)
const path = (s: number) => points.value.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p[s]!)}`).join('')
const ticks = computed(() => [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(f * max.value)))
const labelEvery = computed(() => Math.max(1, Math.ceil((props.days * 56) / (W.value - L))))
const dayLabel = (i: number) => new Date(endOfDay(props.days - 1 - i)).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' })
</script>

<template>
  <div ref="box" class="w-full">
  <svg :viewBox="`0 0 ${W} ${H}`" :width="W" :height="H" class="block" role="img" aria-label="Tren temuan terbuka per severity">
    <g class="text-muted-foreground" fill="currentColor" font-size="11">
      <template v-for="t in ticks" :key="t">
        <line :x1="L" :x2="W - 8" :y1="y(t)" :y2="y(t)" stroke="currentColor" stroke-opacity="0.15" />
        <text :x="L - 6" :y="y(t) + 3" text-anchor="end">{{ t }}</text>
      </template>
      <template v-for="(_, i) in points" :key="i">
        <text v-if="(days - 1 - i) % labelEvery === 0" :x="x(i)" :y="H - 6" :text-anchor="i === 0 ? 'start' : i === days - 1 ? 'end' : 'middle'">{{ dayLabel(i) }}</text>
      </template>
    </g>
    <g v-for="(s, si) in SEVERITIES" :key="s">
      <path :d="path(si)" fill="none" :stroke="SEV_COLOR[s]" stroke-width="2" stroke-linejoin="round" />
      <circle :cx="x(days - 1)" :cy="y(points.at(-1)![si]!)" r="3" :fill="SEV_COLOR[s]">
        <title>{{ s }}: {{ points.at(-1)![si] }}</title>
      </circle>
    </g>
  </svg>
  </div>
</template>
