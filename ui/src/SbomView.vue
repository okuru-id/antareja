<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { save } from '@tauri-apps/plugin-dialog'
import { Boxes, Loader2, Search, AlertTriangle, ShieldCheck, ShieldAlert, FileText, Download, ChevronsUpDown, PackageOpen, Maximize2, Minimize2, Locate } from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import Pager from './Pager.vue'
import { dark } from './store'
import type { Target } from './store'
import Graph from 'graphology'
import { Sigma } from 'sigma'
import forceAtlas2 from 'graphology-layout-forceatlas2'

type Sev = 'critical' | 'high' | 'medium' | 'low'
interface Comp { ref: string; name: string; version: string; type: string; eco: string; license: string; vulns: Record<Sev, number>; total: number; top: Sev | '' }

const targets = ref<Target[]>([])
const scope = ref('')
const comps = ref<Comp[]>([])
const sev = ref<Record<Sev, number>>({ critical: 0, high: 0, medium: 0, low: 0 })
const totalVulns = ref(0)
const meta = ref<{ spec: string; generated: string; root: string; version: string } | null>(null)
const ecosystems = ref<string[]>([])
const graphEl = ref<HTMLDivElement | null>(null)
const rootRef = ref('')
const depsRaw = ref<{ ref: string; dependsOn?: string[] }[]>([])
const graphCount = ref(0)
let sigma: Sigma | null = null
const loading = ref(false)
const error = ref('')
const q = ref('')
const sortKey = ref<'name' | 'version' | 'eco' | 'license' | 'total'>('total')
const sortDir = ref<1 | -1>(-1)
const page = ref(1)
const PER = 12

const sastTargets = computed(() => targets.value.filter((t) => t.kind.type === 'SourcePath'))

onMounted(async () => {
  targets.value = await invoke<Target[]>('list_targets').catch(() => [])
  if (sastTargets.value[0]) scope.value = sastTargets.value[0].id
})

const TYPE_COLOR: Record<string, string> = { Library: '#8b5cf6', Application: '#3b82f6', Framework: '#22d3ee', Lainnya: '#94a3b8' }
const SEV_META: Record<Sev, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#ef4444' },
  high: { label: 'High', color: '#f97316' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#3b82f6' },
}
const LIC_PALETTE = ['#22c55e', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#06b6d4', '#94a3b8']
const ECO_COLOR: Record<string, string> = {
  npm: '#e11d48', composer: '#6d28d9', pypi: '#2563eb', pip: '#2563eb', gem: '#dc2626',
  golang: '#06b6d4', gomod: '#06b6d4', cargo: '#ea580c', maven: '#b45309', nuget: '#512bd4',
  apk: '#64748b', deb: '#64748b', 'conda-pkg': '#16a34a',
}
const ecoColor = (e: string) => ECO_COLOR[e] || '#64748b'

function typeBucket(t: string): keyof typeof TYPE_COLOR {
  if (t === 'library') return 'Library'
  if (t === 'application') return 'Application'
  if (t === 'framework') return 'Framework'
  return 'Lainnya'
}
function ecoOf(c: Record<string, unknown>): string {
  const m = ((c.purl as string) || '').match(/^pkg:([^/]+)\//)
  return m ? m[1] : (c.type as string) || ''
}
function licenseOf(c: Record<string, unknown>): string {
  const ls = (c.licenses as Array<{ license?: { id?: string; name?: string }; expression?: string }>) || []
  const names = ls.map((l) => l.license?.id || l.license?.name || l.expression).filter(Boolean)
  return [...new Set(names)].join(', ')
}
function topSev(v: Record<Sev, number>): Sev | '' {
  return (['critical', 'high', 'medium', 'low'] as Sev[]).find((s) => v[s] > 0) || ''
}

async function generate() {
  if (!scope.value) return
  loading.value = true
  error.value = ''
  try {
    const data = JSON.parse(await invoke<string>('sbom_json', { targetId: scope.value }))
    const list = (data.components || []) as Record<string, unknown>[]
    const byRef = new Map<string, Comp>()
    const out: Comp[] = list.map((c) => {
      const comp: Comp = {
        ref: (c['bom-ref'] as string) || (c.purl as string) || (c.name as string),
        name: (c.name as string) || '?', version: (c.version as string) || '', type: (c.type as string) || '',
        eco: ecoOf(c), license: licenseOf(c), vulns: { critical: 0, high: 0, medium: 0, low: 0 }, total: 0, top: '',
      }
      byRef.set(comp.ref, comp)
      return comp
    })
    // Kerentanan tertanam: hitung per severity (global) & per komponen.
    const sv: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    const vulns = (data.vulnerabilities || []) as Record<string, unknown>[]
    for (const v of vulns) {
      const ratings = (v.ratings as { severity?: string }[]) || []
      const order: Sev[] = ['critical', 'high', 'medium', 'low']
      const s = order.find((o) => ratings.some((r) => (r.severity || '').toLowerCase() === o))
      if (!s) continue
      sv[s]++
      for (const a of (v.affects as { ref?: string }[]) || []) {
        const c = a.ref && byRef.get(a.ref)
        if (c) { c.vulns[s]++; c.total++ }
      }
    }
    for (const c of out) c.top = topSev(c.vulns)
    comps.value = out
    sev.value = sv
    totalVulns.value = vulns.length
    ecosystems.value = [...new Set(out.map((c) => c.eco).filter(Boolean))].slice(0, 6)
    const rootComp = (data.metadata as { component?: Record<string, string> })?.component || {}
    meta.value = {
      spec: `${data.bomFormat || 'CycloneDX'} ${data.specVersion || ''}`.trim(),
      generated: (data.metadata as { timestamp?: string })?.timestamp || '',
      root: rootComp.name || sastTargets.value.find((t) => t.id === scope.value)?.label || 'project',
      version: rootComp.version || '',
    }
    // Graf dependency penuh (komponen + relasi) dirender dengan Sigma.
    rootRef.value = rootComp['bom-ref'] || ''
    depsRaw.value = (data.dependencies || []) as { ref: string; dependsOn?: string[] }[]
    page.value = 1
    q.value = ''
    await nextTick()
    renderGraph()
  } catch (e) {
    error.value = String(e)
    comps.value = []
    meta.value = null
  } finally {
    loading.value = false
  }
}

const PRIMARY = '#2563eb'
const labelHex = () => (dark.value ? '#e5e7eb' : '#334155')
const edgeHex = () => (dark.value ? '#3f4b5e' : '#cbd5e1')

function renderGraph() {
  sigma?.kill()
  sigma = null
  const el = graphEl.value
  if (!el || !comps.value.length) return
  try {
    const byRef = new Map(comps.value.map((c) => [c.ref, c]))
    const g = new Graph()
    const addNode = (ref: string) => {
      if (!ref || g.hasNode(ref)) return
      const c = byRef.get(ref)
      const isRoot = ref === rootRef.value
      g.addNode(ref, {
        label: c ? `${c.name}${c.version ? ' ' + c.version : ''}` : (meta.value?.root || ref),
        x: Math.random(), y: Math.random(),
        size: isRoot ? 11 : 4 + Math.min(9, (c?.total || 0) * 2.5),
        color: isRoot ? PRIMARY : ecoColor(c?.eco || ''),
      })
    }
    for (const c of comps.value) addNode(c.ref)
    addNode(rootRef.value)
    for (const d of depsRaw.value) {
      addNode(d.ref)
      for (const t of d.dependsOn || []) {
        addNode(t)
        if (d.ref !== t && !g.hasEdge(d.ref, t)) g.addEdge(d.ref, t, { size: 1 })
      }
    }
    graphCount.value = g.order
    forceAtlas2.assign(g, { iterations: 300, settings: { gravity: 1.2, scalingRatio: 10, barnesHutOptimize: g.order > 200 } })

    sigma = new Sigma(g, el, {
      labelColor: { color: labelHex() },
      defaultEdgeColor: edgeHex(),
      labelDensity: 0.35, labelGridCellSize: 140, labelRenderedSizeThreshold: 7,
      minCameraRatio: 0.08, maxCameraRatio: 4,
    })

    // Sorot node + tetangga saat hover; redupkan sisanya.
    let hov: string | null = null
    const refresh = () => sigma?.refresh()
    sigma.on('enterNode', ({ node }) => { hov = node; refresh() })
    sigma.on('leaveNode', () => { hov = null; refresh() })
    sigma.setSetting('nodeReducer', (node, dataN) => {
      if (!hov) return dataN
      if (node === hov || g.areNeighbors(hov, node)) return dataN
      return { ...dataN, color: dark.value ? '#334155' : '#e2e8f0', label: '' }
    })
    sigma.setSetting('edgeReducer', (edge, dataE) => {
      if (!hov) return dataE
      return g.hasExtremity(edge, hov) ? { ...dataE, color: PRIMARY, size: 2 } : { ...dataE, hidden: true }
    })
  } catch (e) {
    error.value = `Graf gagal dirender: ${e}`
  }
}

function resetCamera() {
  sigma?.getCamera().animatedReset()
}

const fullscreen = ref(false)
async function toggleFull() {
  fullscreen.value = !fullscreen.value
  await nextTick()
  sigma?.resize()
  sigma?.refresh()
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && fullscreen.value) toggleFull()
}

watch(dark, () => {
  if (!sigma) return
  sigma.setSetting('labelColor', { color: labelHex() })
  sigma.setSetting('defaultEdgeColor', edgeHex())
  sigma.refresh()
})
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => { window.removeEventListener('keydown', onKey); sigma?.kill(); sigma = null })

async function exportFile() {
  const t = sastTargets.value.find((x) => x.id === scope.value)
  if (!t) return
  const name = t.label.split('/').filter(Boolean).at(-1) ?? 'project'
  const path = await save({ defaultPath: `sbom-${name}.cdx.json`, filters: [{ name: 'CycloneDX JSON', extensions: ['json'] }] })
  if (path) await invoke('export_sbom', { targetId: t.id, path }).catch((e) => (error.value = String(e)))
}

// Donut: hitung arc (dasharray + offset) untuk tiap segmen.
const R = 52
const CIRC = 2 * Math.PI * R
function arcs(items: { label: string; value: number; color: string }[]) {
  const total = items.reduce((s, i) => s + i.value, 0) || 1
  let off = 0
  return items.filter((i) => i.value > 0).map((i) => {
    const len = (i.value / total) * CIRC
    const seg = { ...i, pct: (i.value / total) * 100, dash: `${len} ${CIRC - len}`, offset: -off }
    off += len
    return seg
  })
}

const typeData = computed(() => {
  const m: Record<string, number> = { Library: 0, Application: 0, Framework: 0, Lainnya: 0 }
  for (const c of comps.value) m[typeBucket(c.type)]++
  return Object.entries(m).map(([label, value]) => ({ label, value, color: TYPE_COLOR[label] }))
})
const typeArcs = computed(() => arcs(typeData.value))

const licenseData = computed(() => {
  const m = new Map<string, number>()
  for (const c of comps.value) { const k = c.license || 'Tak diketahui'; m.set(k, (m.get(k) || 0) + 1) }
  const sorted = [...m.entries()].sort((a, b) => b[1] - a[1])
  const top = sorted.slice(0, 6)
  const rest = sorted.slice(6).reduce((s, [, v]) => s + v, 0)
  const items = top.map(([label, value], i) => ({ label, value, color: LIC_PALETTE[i] }))
  if (rest) items.push({ label: 'Lainnya', value: rest, color: LIC_PALETTE[6] })
  return items
})
const licenseArcs = computed(() => arcs(licenseData.value))
const licenseCount = computed(() => new Set(comps.value.map((c) => c.license || 'Tak diketahui')).size)

const sevMax = computed(() => Math.max(1, ...Object.values(sev.value)))
const highCritical = computed(() => sev.value.critical + sev.value.high)

const filtered = computed(() => {
  const s = q.value.trim().toLowerCase()
  const list = s ? comps.value.filter((c) => `${c.name} ${c.version} ${c.eco} ${c.license}`.toLowerCase().includes(s)) : comps.value.slice()
  const k = sortKey.value
  return list.sort((a, b) => {
    const r = k === 'total' ? a.total - b.total : String(a[k]).localeCompare(String(b[k]), undefined, { numeric: true })
    return r * sortDir.value
  })
})
const paged = computed(() => filtered.value.slice((page.value - 1) * PER, page.value * PER))
function sortBy(k: typeof sortKey.value) {
  if (sortKey.value === k) sortDir.value = (sortDir.value * -1) as 1 | -1
  else { sortKey.value = k; sortDir.value = k === 'total' ? -1 : 1 }
  page.value = 1
}
const pct = (n: number, d: number) => (d ? ((n / d) * 100).toFixed(1) : '0') + '%'
</script>

<template>
  <main class="w-full space-y-4 px-6 pb-6">
    <!-- Header + pilih target -->
    <Card class="gap-4 px-5">
      <div class="flex flex-wrap items-end gap-3">
        <div class="flex items-center gap-2.5">
          <div class="grid size-10 place-items-center rounded-xl bg-primary/10 text-primary"><Boxes class="size-5" /></div>
          <div>
            <h2 class="font-semibold leading-tight">SBOM Dashboard</h2>
            <p class="text-xs text-muted-foreground">Software Bill of Materials · CycloneDX, offline</p>
          </div>
        </div>
        <div class="ml-auto flex items-end gap-2">
          <div class="min-w-48 space-y-1.5">
            <label class="text-xs font-medium text-muted-foreground">Target folder (SAST)</label>
            <Select v-model="scope">
              <SelectTrigger class="w-full"><SelectValue placeholder="Pilih target…" /></SelectTrigger>
              <SelectContent><SelectItem v-for="t in sastTargets" :key="t.id" :value="t.id">{{ t.label }}</SelectItem></SelectContent>
            </Select>
          </div>
          <Button :disabled="!scope || loading" @click="generate"><Loader2 v-if="loading" class="animate-spin" /><Boxes v-else /> Buat SBOM</Button>
          <Button v-if="comps.length" variant="outline" :disabled="loading" @click="exportFile"><Download /> Export</Button>
        </div>
      </div>
      <p v-if="!sastTargets.length" class="text-sm text-muted-foreground">Belum ada target folder. Tambahkan target SAST (folder project) di tab Target dulu.</p>
      <p v-if="error" class="flex items-start gap-1.5 text-sm text-destructive"><AlertTriangle class="mt-px size-4 shrink-0" /> {{ error }}</p>
      <div v-if="meta" class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span class="font-semibold">{{ meta.root }}</span>
        <span v-if="meta.version" class="rounded bg-primary/10 px-1.5 py-0.5 text-xs font-medium text-primary">v{{ meta.version }}</span>
        <span class="text-muted-foreground">·</span>
        <span v-for="e in ecosystems" :key="e" class="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground"><PackageOpen class="size-3" /> {{ e }}</span>
        <span class="ml-auto text-xs text-muted-foreground">{{ meta.spec }}<template v-if="meta.generated"> · {{ new Date(meta.generated).toLocaleString('id-ID') }}</template></span>
      </div>
    </Card>

    <template v-if="comps.length">
      <!-- Stat cards -->
      <div class="grid grid-cols-2 gap-3 @3xl:grid-cols-4">
        <Card class="!flex-row items-center gap-3 px-4 py-3.5">
          <div class="grid size-10 place-items-center rounded-lg bg-blue-500/10 text-blue-500"><Boxes class="size-5" /></div>
          <div><div class="text-xs text-muted-foreground">Total komponen</div><div class="text-2xl font-semibold tabular-nums">{{ comps.length }}</div></div>
        </Card>
        <Card class="!flex-row items-center gap-3 px-4 py-3.5">
          <div class="grid size-10 place-items-center rounded-lg bg-red-500/10 text-red-500"><ShieldAlert class="size-5" /></div>
          <div><div class="text-xs text-muted-foreground">Kerentanan</div><div class="text-2xl font-semibold tabular-nums">{{ totalVulns }}</div></div>
        </Card>
        <Card class="!flex-row items-center gap-3 px-4 py-3.5">
          <div class="grid size-10 place-items-center rounded-lg bg-orange-500/10 text-orange-500"><AlertTriangle class="size-5" /></div>
          <div><div class="text-xs text-muted-foreground">High &amp; Critical</div><div class="text-2xl font-semibold tabular-nums">{{ highCritical }}</div></div>
        </Card>
        <Card class="!flex-row items-center gap-3 px-4 py-3.5">
          <div class="grid size-10 place-items-center rounded-lg bg-violet-500/10 text-violet-500"><FileText class="size-5" /></div>
          <div><div class="text-xs text-muted-foreground">Lisensi</div><div class="text-2xl font-semibold tabular-nums">{{ licenseCount }}</div></div>
        </Card>
      </div>

      <!-- Charts -->
      <div class="grid gap-3 @4xl:grid-cols-3">
        <!-- Donut tipe -->
        <Card class="gap-3 px-5">
          <h3 class="text-sm font-semibold">Komponen per Tipe</h3>
          <div class="flex items-center gap-4">
            <div class="relative size-32 shrink-0">
              <svg viewBox="0 0 120 120" class="size-32 -rotate-90">
                <circle cx="60" cy="60" :r="R" fill="none" class="stroke-muted" stroke-width="14" />
                <circle v-for="s in typeArcs" :key="s.label" cx="60" cy="60" :r="R" fill="none" :stroke="s.color" stroke-width="14" :stroke-dasharray="s.dash" :stroke-dashoffset="s.offset" />
              </svg>
              <div class="absolute inset-0 grid place-items-center text-center"><div><div class="text-xl font-semibold tabular-nums leading-none">{{ comps.length }}</div><div class="text-[10px] text-muted-foreground">Komponen</div></div></div>
            </div>
            <ul class="min-w-0 flex-1 space-y-1.5 text-sm">
              <li v-for="d in typeData" :key="d.label" class="flex items-center gap-2">
                <span class="size-2.5 shrink-0 rounded-sm" :style="{ background: d.color }" />
                <span class="truncate">{{ d.label }}</span>
                <span class="ml-auto tabular-nums text-muted-foreground">{{ pct(d.value, comps.length) }} <span class="text-foreground">({{ d.value }})</span></span>
              </li>
            </ul>
          </div>
        </Card>

        <!-- Severity bars -->
        <Card class="gap-3 px-5">
          <h3 class="text-sm font-semibold">Kerentanan per Severity</h3>
          <ul class="space-y-2.5 pt-1">
            <li v-for="(m, s) in SEV_META" :key="s" class="flex items-center gap-3 text-sm">
              <span class="w-14 shrink-0" :style="{ color: m.color }">{{ m.label }}</span>
              <div class="h-3 flex-1 overflow-hidden rounded-full bg-muted">
                <div class="h-full rounded-full transition-[width] duration-500" :style="{ width: (sev[s] / sevMax * 100) + '%', background: m.color }" />
              </div>
              <span class="w-6 shrink-0 text-right tabular-nums">{{ sev[s] }}</span>
            </li>
          </ul>
          <p v-if="!totalVulns" class="flex items-center gap-1.5 pt-1 text-xs text-green-600 dark:text-green-400"><ShieldCheck class="size-3.5" /> Tidak ada kerentanan terdeteksi.</p>
        </Card>

        <!-- Donut lisensi -->
        <Card class="gap-3 px-5">
          <h3 class="text-sm font-semibold">Distribusi Lisensi</h3>
          <div class="flex items-center gap-4">
            <div class="relative size-32 shrink-0">
              <svg viewBox="0 0 120 120" class="size-32 -rotate-90">
                <circle cx="60" cy="60" :r="R" fill="none" class="stroke-muted" stroke-width="14" />
                <circle v-for="s in licenseArcs" :key="s.label" cx="60" cy="60" :r="R" fill="none" :stroke="s.color" stroke-width="14" :stroke-dasharray="s.dash" :stroke-dashoffset="s.offset" />
              </svg>
              <div class="absolute inset-0 grid place-items-center text-center"><div><div class="text-xl font-semibold tabular-nums leading-none">{{ licenseCount }}</div><div class="text-[10px] text-muted-foreground">Lisensi</div></div></div>
            </div>
            <ul class="min-w-0 flex-1 space-y-1.5 text-sm">
              <li v-for="d in licenseData" :key="d.label" class="flex items-center gap-2">
                <span class="size-2.5 shrink-0 rounded-sm" :style="{ background: d.color }" />
                <span class="truncate">{{ d.label }}</span>
                <span class="ml-auto shrink-0 tabular-nums text-muted-foreground">{{ pct(d.value, comps.length) }}</span>
              </li>
            </ul>
          </div>
        </Card>
      </div>

      <div class="grid gap-3 @5xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <!-- Component list -->
        <Card class="gap-0 overflow-hidden p-0">
          <div class="flex items-center gap-2 p-3">
            <h3 class="text-sm font-semibold">Daftar Komponen</h3>
            <div class="relative ml-auto max-w-56 flex-1">
              <Search class="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input v-model="q" placeholder="Cari komponen…" class="h-9 rounded-full border-border bg-card pl-9" @update:model-value="page = 1" />
            </div>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead class="border-y bg-muted/40 text-left text-xs text-muted-foreground">
                <tr>
                  <th v-for="col in (['name','version','license','total'] as const)" :key="col" class="cursor-pointer px-4 py-2 font-medium whitespace-nowrap select-none hover:text-foreground" :class="col === 'total' && 'text-right'" @click="sortBy(col)">
                    <span class="inline-flex items-center gap-1">{{ { name: 'Komponen', version: 'Versi', license: 'Lisensi', total: 'Kerentanan' }[col] }}<ChevronsUpDown class="size-3 opacity-50" :class="sortKey === col && 'text-foreground opacity-100'" /></span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(c, i) in paged" :key="i" class="border-b last:border-0 hover:bg-muted/30">
                  <td class="px-4 py-2">
                    <div class="font-medium break-all">{{ c.name }}</div>
                    <div v-if="c.eco" class="text-[11px] text-muted-foreground">{{ c.eco }}</div>
                  </td>
                  <td class="px-4 py-2 tabular-nums whitespace-nowrap text-muted-foreground">{{ c.version || '—' }}</td>
                  <td class="px-4 py-2"><span class="text-xs text-muted-foreground">{{ c.license || 'tak diketahui' }}</span></td>
                  <td class="px-4 py-2 text-right">
                    <span v-if="c.total" class="inline-flex min-w-6 items-center justify-center rounded px-1.5 py-0.5 text-xs font-semibold text-white tabular-nums" :style="{ background: c.top ? SEV_META[c.top].color : '#64748b' }">{{ c.total }}</span>
                    <span v-else class="inline-flex min-w-6 items-center justify-center rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground tabular-nums">0</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <Pager v-model="page" :total="filtered.length" :per="PER" />
        </Card>

        <!-- Dependency graph (Sigma.js) -->
        <Card class="gap-3 px-5">
          <div class="flex items-center gap-2">
            <h3 class="text-sm font-semibold">Dependency Graph</h3>
            <span v-if="graphCount" class="text-xs text-muted-foreground tabular-nums">{{ graphCount }} node</span>
          </div>
          <div :class="fullscreen ? 'fixed inset-x-0 top-9 bottom-7 z-40 border-y bg-background' : 'relative min-h-80 flex-1 overflow-hidden rounded-lg border bg-muted/20'">
            <div ref="graphEl" class="absolute inset-0" />
            <span v-if="fullscreen" class="absolute top-3 left-3 z-10 rounded-md bg-card/90 px-2.5 py-1 text-xs font-medium shadow-sm">Dependency Graph · {{ graphCount }} node</span>
            <div class="absolute top-2 right-2 z-10 flex items-center gap-1">
              <Button variant="secondary" size="icon-sm" title="Pusatkan tampilan" @click="resetCamera"><Locate /></Button>
              <Button variant="secondary" size="icon-sm" :title="fullscreen ? 'Keluar layar penuh (Esc)' : 'Layar penuh'" @click="toggleFull">
                <Minimize2 v-if="fullscreen" /><Maximize2 v-else />
              </Button>
            </div>
          </div>
          <p class="text-center text-[11px] text-muted-foreground">Ukuran node = jumlah kerentanan · warna = ekosistem · seret untuk geser, scroll untuk zoom, hover untuk menyorot.</p>
        </Card>
      </div>
    </template>
  </main>
</template>
