<script setup lang="ts">
import { computed } from 'vue'
import { ChevronLeft, ChevronRight } from '@lucide/vue'
import { Button } from '@/components/ui/button'

const props = defineProps<{ total: number; per: number }>()
const page = defineModel<number>({ required: true })
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.per)))
const from = computed(() => (props.total ? (page.value - 1) * props.per + 1 : 0))
const to = computed(() => Math.min(page.value * props.per, props.total))
</script>

<template>
  <div v-if="total > per" class="flex items-center gap-1 border-t px-4 py-2 text-xs text-muted-foreground">
    <span class="mr-auto tabular-nums">{{ from }}–{{ to }} dari {{ total }}</span>
    <Button variant="ghost" size="icon-sm" title="Sebelumnya" :disabled="page <= 1" @click="page--"><ChevronLeft /></Button>
    <Button v-for="p in pages" :key="p" size="icon-sm" :variant="p === page ? 'secondary' : 'ghost'" class="tabular-nums" @click="page = p">{{ p }}</Button>
    <Button variant="ghost" size="icon-sm" title="Berikutnya" :disabled="page >= pages" @click="page++"><ChevronRight /></Button>
  </div>
</template>
