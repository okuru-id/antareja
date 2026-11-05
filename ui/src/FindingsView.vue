<script setup lang="ts">
import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { AlertTriangle, FileCode2, Globe, Link2 } from '@lucide/vue'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { type Finding, type Status, SEVERITIES, STATUS_LABEL, sevClass, scans as data, findingsQuery } from './store'

const fTarget = ref(findingsQuery.value.target)
const fSeverity = ref(findingsQuery.value.severity)
findingsQuery.value = { target: 'all', severity: 'all' }
const fMode = ref('all')
const fStatus = ref('Open') // default: yang masih perlu ditindaklanjuti


const scoped = computed(() => data.value.filter((d) => fTarget.value === 'all' || d.target.id === fTarget.value))
const all = computed(() =>
  scoped.value.flatMap((d) => d.scan.findings.map((f) => ({ ...f, target: d.target.label })))
    .filter((f) => (fMode.value === 'all' || f.mode === fMode.value) && (fStatus.value === 'all' || f.status === fStatus.value)),
)
const shown = computed(() =>
  all.value.filter((f) => fSeverity.value === 'all' || f.severity === fSeverity.value)
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)),
)
const count = (s: string) => all.value.filter((f: Finding) => f.severity === s).length
async function setStatus(id: string, status: Status) {
  await invoke('set_finding_status', { id, status })
  for (const d of data.value) for (const f of d.scan.findings) if (f.id === id) f.status = status
}
const when = (iso: string) => new Date(iso).toLocaleString('id-ID')
</script>

<template>
  <main class="w-full space-y-4 px-6 pb-6">
    <div v-if="!data.length" class="py-16 text-center text-sm text-muted-foreground">
      Belum ada hasil scan. Jalankan scan dari Dashboard atau menu Target.
    </div>

    <template v-else>
      <div class="grid grid-cols-5 gap-2">
        <button v-for="s in SEVERITIES" :key="s" class="rounded-lg border bg-card p-3 text-left transition-colors hover:bg-muted"
          :class="fSeverity === s && 'ring-2 ring-ring'" @click="fSeverity = fSeverity === s ? 'all' : s">
          <div class="text-2xl font-semibold tabular-nums">{{ count(s) }}</div>
          <div class="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span class="size-2 rounded-full" :class="sevClass[s]" /> {{ s }}
          </div>
        </button>
      </div>

      <div class="flex flex-wrap gap-2">
        <Select v-model="fTarget">
          <SelectTrigger class="w-56"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua target</SelectItem>
            <SelectItem v-for="d in data" :key="d.target.id" :value="d.target.id">{{ d.target.label }}</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="fSeverity">
          <SelectTrigger class="w-40"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua severity</SelectItem>
            <SelectItem v-for="s in SEVERITIES" :key="s" :value="s">{{ s }}</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="fMode">
          <SelectTrigger class="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua mode</SelectItem>
            <SelectItem value="Sast">SAST</SelectItem>
            <SelectItem value="Dast">DAST</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="fStatus">
          <SelectTrigger class="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua status</SelectItem>
            <SelectItem v-for="(label, s) in STATUS_LABEL" :key="s" :value="s">{{ label }}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <template v-for="d in scoped" :key="d.scan.id">
        <Alert v-if="d.scan.errors.length">
          <AlertTriangle />
          <AlertTitle>Scan "{{ d.target.label }}" ({{ when(d.scan.started_at) }}) selesai sebagian</AlertTitle>
          <AlertDescription>
            <p v-for="e in d.scan.errors" :key="e" class="break-all">{{ e }}</p>
          </AlertDescription>
        </Alert>
      </template>

      <p class="text-xs text-muted-foreground">
        {{ shown.length }} temuan dari scan terakhir. Status Risiko diterima / False positive terbawa ke scan berikutnya. Tool otomatis tidak menemukan logic flaw / auth bypass, jadi review manual tetap perlu.
      </p>

      <Card class="gap-0 py-0">
        <Accordion type="multiple">
          <AccordionItem v-for="f in shown" :key="f.id" :value="f.id" class="px-4">
            <AccordionTrigger class="items-center gap-3 hover:no-underline">
              <span class="w-16 shrink-0 rounded px-1.5 py-0.5 text-center text-[11px] font-semibold" :class="sevClass[f.severity]">{{ f.severity }}</span>
              <span class="min-w-0 flex-1">
                <span class="block truncate">{{ f.title }}</span>
                <span class="flex items-center gap-1 truncate font-mono text-xs font-normal text-muted-foreground">
                  <component :is="f.mode === 'Dast' ? Globe : FileCode2" class="size-3 shrink-0" />{{ f.location }}
                </span>
              </span>
              <Badge v-if="f.confirmed" class="shrink-0 gap-1 bg-violet-600 text-white"><Link2 class="size-3" />Terkonfirmasi</Badge>
              <Badge v-if="f.status !== 'Open'" variant="secondary" class="shrink-0">{{ STATUS_LABEL[f.status] }}</Badge>
              <Badge variant="outline" class="shrink-0">{{ f.tool }}</Badge>
              <span class="hidden w-28 shrink-0 truncate text-xs font-normal text-muted-foreground sm:block">{{ f.target }}</span>
            </AccordionTrigger>
            <AccordionContent class="space-y-3 pb-4 pl-[76px] text-sm">
              <section v-if="f.confirmed" class="rounded-md border border-violet-500/40 bg-violet-500/10 p-3">
                <h4 class="font-medium">Korelasi DAST↔SAST</h4>
                <p class="text-muted-foreground">{{ f.confirmed }}</p>
              </section>
              <section>
                <h4 class="font-medium">Apa masalahnya</h4>
                <p class="whitespace-pre-line text-muted-foreground">{{ f.description || '-' }}</p>
              </section>
              <section>
                <h4 class="font-medium">Kenapa berbahaya</h4>
                <p class="whitespace-pre-line text-muted-foreground">{{ f.impact || '-' }}</p>
              </section>
              <section>
                <h4 class="font-medium">Cara memperbaiki</h4>
                <p class="whitespace-pre-line break-all text-muted-foreground">{{ f.recommendation || '-' }}</p>
              </section>
              <section v-if="f.evidence">
                <h4 class="font-medium">Bukti</h4>
                <pre class="mt-1 max-h-72 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">{{ f.evidence }}</pre>
              </section>
              <div class="flex flex-wrap items-center gap-3 pt-1">
                <Select :model-value="f.status" @update:model-value="(v) => setStatus(f.id, v as Status)">
                  <SelectTrigger size="sm" class="w-44"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="(label, s) in STATUS_LABEL" :key="s" :value="s">{{ label }}</SelectItem>
                  </SelectContent>
                </Select>
                <span v-if="f.rule_id" class="font-mono text-xs text-muted-foreground">rule: {{ f.rule_id }}</span>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
        <p v-if="!shown.length" class="p-6 text-center text-sm text-muted-foreground">Tidak ada temuan untuk filter ini.</p>
      </Card>
    </template>
  </main>
</template>
