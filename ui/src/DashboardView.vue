<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  TriangleAlert, Layers, ShieldCheck, Info, ArrowUp, ArrowDown, Play, Plus, FileText, Search, FolderOpen, Globe, Loader2, ChevronRight, Lightbulb, Link2, Crosshair, History,
  ChevronsUpDown,
} from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import TrendChart from './TrendChart.vue'
import Pager from './Pager.vue'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  type Severity, type Target, SEVERITIES, SEV_COLOR, targets, scans, history, progress, openFindings, runScan, showFindings, tab, ago,
  postureAt, endOfDay,
} from './store'

const SEV_ICON = { Critical: TriangleAlert, High: TriangleAlert, Medium: Layers, Low: ShieldCheck, Info }

const open = computed(() => scans.value.flatMap((d) => openFindings(d.scan)))
const total = computed(() => open.value.length)
const count = (s: Severity) => open.value.filter((f) => f.severity === s).length
const pct = (n: number) => (total.value ? Math.round((n / total.value) * 1000) / 10 : 0)

// Donut: conic-gradient dari proporsi tiap severity.
const donut = computed(() => {
  let acc = 0
  const stops = SEVERITIES.map((s) => {
    const from = acc
    acc += pct(count(s))
    return `${SEV_COLOR[s]} ${from}% ${acc}%`
  })
  return total.value ? `conic-gradient(${stops.join(',')})` : 'var(--muted)'
})

// Tren: posture akhir tiap hari; kartu severity membandingkan dengan 7 hari lalu.
const days = ref('7')
const week = computed(() => Array.from({ length: 8 }, (_, i) => postureAt(endOfDay(7 - i))))
// Mulai dari hari pertama yang punya data, agar riwayat pendek tidak tampil sebagai garis 0 lalu lonjakan.
const from = computed(() => Math.min(week.value.findIndex((p) => p.some((n) => n > 0)) >>> 0, 6))
const spark = (si: number) => {
  // Skala min..maks agar naik-turun terlihat (data datar = garis tengah).
  const v = week.value.slice(from.value).map((p) => p[si]!)
  const lo = Math.min(...v), hi = Math.max(...v)
  return v.map((n, i) => `${(i * 100) / (v.length - 1)},${hi === lo ? 16 : 27 - ((n - lo) / (hi - lo)) * 23}`).join(' ')
}
// Dibanding hari pertama dengan data dalam 7 hari terakhir; null = tak ada pembanding.
const since = computed(() => (from.value === 0 ? '7 hari lalu' : new Date(endOfDay(7 - from.value)).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' })))
const delta = (si: number) => {
  const prev = week.value[from.value]![si]!, now = count(SEVERITIES[si]!)
  return prev ? Math.round(((now - prev) / prev) * 100) : null
}

// Tabel target
const q = ref('')
const kind = ref('all')
const scanOf = (t: Target) => scans.value.find((d) => d.target.id === t.id)?.scan
const label = (id: string | null) => targets.value.find((t) => t.id === id)?.label
const rows = computed(() =>
  targets.value.filter((t) =>
    (kind.value === 'all' || t.kind.type === kind.value) &&
    `${t.label} ${t.kind.value}`.toLowerCase().includes(q.value.toLowerCase())),
)

// Urut per kolom; default: aktivitas terbaru (scan terakhir, atau waktu ditambahkan) di atas.
type Col = 'label' | 'kind' | 'when' | 'found'
const sort = ref<{ col: Col; desc: boolean }>({ col: 'when', desc: true })
const keyOf = (t: Target, c: Col): string | number => {
  const sc = scanOf(t)
  if (c === 'label') return t.label.toLowerCase()
  if (c === 'kind') return t.kind.type
  if (c === 'when') return new Date(sc?.started_at ?? t.created_at).getTime()
  return sc ? openFindings(sc).length : -1
}
const sorted = computed(() => {
  const { col, desc } = sort.value
  return [...rows.value].sort((a, b) => {
    const x = keyOf(a, col), y = keyOf(b, col)
    return (x < y ? -1 : x > y ? 1 : 0) * (desc ? -1 : 1)
  })
})
// Klik kolom yang sama membalik arah; kolom angka/waktu mulai dari terbesar.
const sortBy = (col: Col) =>
  (sort.value = sort.value.col === col ? { col, desc: !sort.value.desc } : { col, desc: col === 'when' || col === 'found' })
const COLS: { col: Col; label: string; cls: string }[] = [
  { col: 'label', label: 'Target', cls: 'w-full px-4' },
  { col: 'kind', label: 'Jenis', cls: 'px-2' },
  { col: 'when', label: 'Status', cls: 'px-2' },
  { col: 'found', label: 'Temuan', cls: 'px-2 justify-end' },
]

// Halaman 5 baris; kembali ke halaman 1 saat filter/urutan berubah.
const PER = 5
const page = ref(1)
const hPage = ref(1)
const slice = <T,>(list: T[], p: number) => list.slice((p - 1) * PER, p * PER)
watch([q, kind, sort], () => (page.value = hPage.value = 1))

// Riwayat: terbaru dulu; ikut filter pencarian/jenis yang sama.
const view = ref<'targets' | 'history'>('targets')
const historyRows = computed(() => {
  const ok = new Set(rows.value.map((t) => t.id))
  return history.value.filter((h) => ok.has(h.target_id)).slice().reverse()
})
const targetOf = (id: string) => targets.value.find((t) => t.id === id)
const duration = (a: string, b: string | null) => {
  if (!b) return '–'
  const s = Math.round((new Date(b).getTime() - new Date(a).getTime()) / 1000)
  return s < 60 ? `${s} dtk` : `${Math.floor(s / 60)} mnt ${s % 60} dtk`
}

async function scan(t: Target) {
  try { await runScan(t) } catch { /* error tampil di panel log */ }
}
// Satu per satu agar tidak membanjiri jaringan/CPU.
async function scanAll() {
  for (const t of targets.value) if (!(t.id in progress.value)) await scan(t)
}

const insights = computed(() => {
  const out: { icon: unknown; color: string; title: string; text: string }[] = []
  const crit = count('Critical')
  if (crit) out.push({ icon: TriangleAlert, color: 'text-red-600', title: `${crit} temuan kritis`, text: 'Perbaiki lebih dulu: risiko kompromi langsung.' })
  const mh = count('Medium') + count('High')
  if (total.value) out.push({ icon: Layers, color: 'text-amber-500', title: `${Math.round(pct(mh))}% temuan Medium–High`, text: 'Fokus berikutnya setelah temuan kritis.' })
  const week = Date.now() - 7 * 864e5
  const recent = scans.value.filter((d) => new Date(d.scan.started_at).getTime() > week).length
  out.push({ icon: ShieldCheck, color: 'text-primary', title: `${targets.value.length} target terdaftar`, text: `${recent} sudah dipindai dalam 7 hari terakhir.` })
  const never = targets.value.length - scans.value.length
  if (never > 0) out.push({ icon: Info, color: 'text-muted-foreground', title: `${never} target belum pernah di-scan`, text: 'Jalankan scan untuk melihat temuannya.' })
  return out
})
</script>

<template>
  <main class="grid gap-4 px-6 pb-6 @5xl:grid-cols-[minmax(0,1fr)_280px]">
    <div class="min-w-0 space-y-4">
      <!-- Kartu severity -->
      <div class="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-3">
        <button v-for="(s, si) in SEVERITIES" :key="s" class="flex min-w-0 items-start gap-3 rounded-xl border bg-card p-3.5 text-left shadow-xs transition-colors hover:bg-muted/50"
          @click="showFindings('all', s)">
          <span class="grid size-10 shrink-0 place-items-center rounded-full" :style="{ background: SEV_COLOR[s] + '1f', color: SEV_COLOR[s] }">
            <component :is="SEV_ICON[s]" class="size-5" />
          </span>
          <span class="min-w-0 flex-1">
            <span class="block text-sm text-muted-foreground">{{ s }}</span>
            <span class="block text-2xl leading-tight font-semibold tabular-nums">{{ count(s) }}</span>
            <!-- Dibanding hari pertama dengan data. Naik = memburuk (warna severity), turun = membaik (hijau). -->
            <span v-if="delta(si) !== null" class="mt-0.5 flex items-center gap-0.5 text-xs font-medium tabular-nums" :title="`Dibanding ${since}`"
              :style="delta(si)! > 0 ? { color: SEV_COLOR[s] } : {}" :class="delta(si)! < 0 ? 'text-green-600 dark:text-green-500' : delta(si) === 0 && 'text-muted-foreground'">
              <ArrowUp v-if="delta(si)! > 0" class="size-3" /><ArrowDown v-else-if="delta(si)! < 0" class="size-3" />{{ Math.abs(delta(si)!) }}%<span class="font-normal text-muted-foreground">&nbsp;vs {{ since }}</span>
            </span>
            <span v-else class="mt-0.5 block text-xs text-muted-foreground" title="Belum ada data pembanding">Belum ada pembanding</span>
            <!-- Sparkline 7 hari + area gradien -->
            <svg viewBox="0 0 100 30" preserveAspectRatio="none" class="mt-1.5 block h-7 w-full" aria-hidden="true">
              <defs>
                <linearGradient :id="`spark-${s}`" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" :stop-color="SEV_COLOR[s]" stop-opacity="0.3" />
                  <stop offset="1" :stop-color="SEV_COLOR[s]" stop-opacity="0" />
                </linearGradient>
              </defs>
              <polygon :points="`0,30 ${spark(si)} 100,30`" :fill="`url(#spark-${s})`" />
              <polyline :points="spark(si)" fill="none" :stroke="SEV_COLOR[s]" stroke-width="1.75" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
            </svg>
          </span>
        </button>
      </div>

      <div class="grid grid-cols-[repeat(auto-fit,minmax(min(100%,320px),1fr))] gap-4">
        <!-- Tren -->
        <Card class="gap-3 px-5">
          <div class="flex items-center justify-between gap-2">
            <h2 class="font-semibold">Tren temuan terbuka</h2>
            <Select v-model="days">
              <SelectTrigger size="sm" class="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="7">7 hari terakhir</SelectItem>
                <SelectItem value="30">30 hari terakhir</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <TrendChart :days="Number(days)" />
          <p v-if="!history.length" class="text-sm text-muted-foreground">Belum ada riwayat scan.</p>
        </Card>

        <!-- Donut -->
        <Card class="gap-4 px-5">
          <h2 class="font-semibold">Total temuan terbuka</h2>
          <div class="flex flex-1 flex-wrap content-center items-center justify-center gap-x-8 gap-y-4">
            <div class="grid size-36 shrink-0 place-items-center rounded-full" :style="{ background: donut }">
              <div class="grid size-24 place-items-center rounded-full bg-card text-center">
                <div><div class="text-2xl font-semibold tabular-nums">{{ total }}</div><div class="text-xs text-muted-foreground">temuan</div></div>
              </div>
            </div>
            <div class="max-w-80 min-w-44 flex-1 space-y-2 text-sm">
              <button v-for="s in SEVERITIES" :key="s" class="flex w-full items-center gap-2 hover:underline" @click="showFindings('all', s)">
                <span class="size-2.5 rounded-full" :style="{ background: SEV_COLOR[s] }" />
                <span class="flex-1 text-left">{{ s }}</span>
                <span class="w-10 text-right tabular-nums">{{ count(s) }}</span>
                <span class="w-12 text-right tabular-nums text-muted-foreground">{{ pct(count(s)) }}%</span>
              </button>
            </div>
          </div>
        </Card>
      </div>

      <!-- Tabel target / riwayat scan -->
      <Card class="gap-0 py-0">
        <div class="flex gap-1 border-b px-3">
          <button v-for="v in [{ k: 'targets', icon: Crosshair, t: `Target (${targets.length})` }, { k: 'history', icon: History, t: `Riwayat scan (${history.length})` }]" :key="v.k"
            class="-mb-px flex items-center gap-2 border-b-2 px-3 py-3 text-sm transition-colors"
            :class="view === v.k ? 'border-primary font-medium text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'"
            @click="view = v.k as 'targets' | 'history'">
            <component :is="v.icon" class="size-4" /> {{ v.t }}
          </button>
        </div>
        <div class="flex flex-wrap items-center gap-2 border-b p-3">
          <div class="relative min-w-48 flex-1">
            <Search class="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input v-model="q" placeholder="Cari target atau label…" class="pl-8" />
          </div>
          <Select v-model="kind">
            <SelectTrigger class="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Semua jenis</SelectItem>
              <SelectItem value="SourcePath">SAST (folder)</SelectItem>
              <SelectItem value="Url">DAST (URL)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div v-if="view === 'targets'" class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-xs text-muted-foreground">
              <tr class="border-b">
                <th v-for="c in COLS" :key="c.col" class="py-1 font-medium" :class="c.cls.replace('justify-end', '')" :aria-sort="sort.col === c.col ? (sort.desc ? 'descending' : 'ascending') : 'none'">
                  <button class="-mx-1.5 inline-flex w-[calc(100%+0.75rem)] items-center gap-1 rounded px-1.5 py-1 whitespace-nowrap hover:bg-muted hover:text-foreground"
                    :class="[c.cls.includes('justify-end') && 'justify-end', sort.col === c.col && 'text-foreground']" @click="sortBy(c.col)">
                    {{ c.label }}
                    <ArrowDown v-if="sort.col === c.col && sort.desc" class="size-3" />
                    <ArrowUp v-else-if="sort.col === c.col" class="size-3" />
                    <ChevronsUpDown v-else class="size-3 opacity-40" />
                  </button>
                </th>
                <th class="px-4 py-2 text-right font-medium">Aksi</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in slice(sorted, page)" :key="t.id" class="border-b last:border-0 hover:bg-muted/40">
                <td class="max-w-0 px-4 py-2.5">
                  <div class="flex items-center gap-2.5">
                    <component :is="t.kind.type === 'Url' ? Globe : FolderOpen" class="size-4 shrink-0 text-muted-foreground" />
                    <div class="min-w-0">
                      <div class="truncate font-medium">{{ t.label }}</div>
                      <div class="flex items-center gap-1 truncate text-xs text-muted-foreground">
                        <template v-if="t.label !== t.kind.value">{{ t.kind.value }}</template>
                        <span v-if="t.linked" class="inline-flex items-center gap-0.5 rounded bg-violet-500/10 px-1 text-violet-600 dark:text-violet-400"><Link2 class="size-3" />{{ label(t.linked) }}</span>
                      </div>
                    </div>
                  </div>
                </td>
                <td class="px-2">
                  <span class="rounded-md px-2 py-0.5 text-xs font-semibold" :class="t.kind.type === 'Url' ? 'bg-violet-500/10 text-violet-600 dark:text-violet-400' : 'bg-primary/10 text-primary'">
                    {{ t.kind.type === 'Url' ? 'DAST' : 'SAST' }}
                  </span>
                </td>
                <td class="px-2 whitespace-nowrap">
                  <span v-if="t.id in progress" class="inline-flex items-center gap-1.5 text-primary"><Loader2 class="size-3.5 animate-spin" />Memindai</span>
                  <span v-else-if="scanOf(t)" class="inline-flex items-center gap-1.5" :title="new Date(scanOf(t)!.started_at).toLocaleString('id-ID')">
                    <span class="size-2 rounded-full" :class="scanOf(t)!.errors.length ? 'bg-amber-500' : 'bg-green-500'" />
                    {{ scanOf(t)!.errors.length ? 'Sebagian' : 'Selesai' }}
                    <span class="text-xs text-muted-foreground">· {{ ago(scanOf(t)!.started_at) }}</span>
                  </span>
                  <span v-else class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="size-2 rounded-full bg-muted-foreground/40" />Belum di-scan</span>
                </td>
                <td class="px-2 text-right tabular-nums">
                  <span v-if="scanOf(t)" class="font-medium" :class="openFindings(scanOf(t)).some((f) => f.severity === 'Critical') && 'text-red-600'">{{ openFindings(scanOf(t)).length }}</span>
                  <span v-else class="text-muted-foreground">–</span>
                </td>
                <td class="px-4 text-right whitespace-nowrap">
                  <Button variant="outline" size="icon-sm" title="Scan" :disabled="t.id in progress" @click="scan(t)"><Play /></Button>
                  <Button variant="ghost" size="icon-sm" title="Lihat temuan" :disabled="!scanOf(t)" @click="showFindings(t.id)"><ChevronRight /></Button>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="!rows.length" class="p-6 text-center text-sm text-muted-foreground">
            {{ targets.length ? 'Tidak ada target yang cocok.' : 'Belum ada target. Tambahkan dulu di menu Target.' }}
          </p>
          <Pager v-model="page" :total="sorted.length" :per="PER" />
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-xs text-muted-foreground">
              <tr class="border-b">
                <th class="w-full px-4 py-2 font-medium">Target</th>
                <th class="px-2 py-2 font-medium whitespace-nowrap">Waktu</th>
                <th class="px-2 py-2 font-medium">Durasi</th>
                <th class="px-4 py-2 text-right font-medium whitespace-nowrap">Temuan terbuka</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="h in slice(historyRows, hPage)" :key="h.id" class="border-b last:border-0 hover:bg-muted/40">
                <td class="max-w-0 px-4 py-2.5">
                  <div class="flex items-center gap-2.5">
                    <component :is="targetOf(h.target_id)?.kind.type === 'Url' ? Globe : FolderOpen" class="size-4 shrink-0 text-muted-foreground" />
                    <span class="truncate font-medium">{{ targetOf(h.target_id)?.label }}</span>
                    <span v-if="h.errors" class="shrink-0 rounded bg-amber-500/15 px-1.5 text-xs text-amber-700 dark:text-amber-400">{{ h.errors }} modul gagal</span>
                  </div>
                </td>
                <td class="px-2 whitespace-nowrap" :title="ago(h.started_at)">{{ new Date(h.started_at).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' }) }}</td>
                <td class="px-2 whitespace-nowrap text-muted-foreground">{{ duration(h.started_at, h.finished_at) }}</td>
                <td class="px-4">
                  <div class="flex justify-end gap-1">
                    <span v-for="(n, si) in h.open" :key="si" class="min-w-7 rounded px-1 text-center text-xs font-medium tabular-nums"
                      :style="n ? { background: SEV_COLOR[SEVERITIES[si]!] + '26', color: SEV_COLOR[SEVERITIES[si]!] } : {}"
                      :class="!n && 'text-muted-foreground/50'" :title="SEVERITIES[si]">{{ n }}</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="!historyRows.length" class="p-6 text-center text-sm text-muted-foreground">Belum ada riwayat scan.</p>
          <Pager v-model="hPage" :total="historyRows.length" :per="PER" />
        </div>
      </Card>
    </div>

    <!-- Kolom kanan -->
    <div class="space-y-4">
      <Card class="gap-2 px-4">
        <Button size="lg" :disabled="!targets.length" @click="scanAll"><Play /> Scan semua target</Button>
        <Button variant="outline" @click="tab = 'targets'"><Plus /> Tambah target</Button>
        <Button variant="outline" @click="tab = 'report'"><FileText /> Buat laporan</Button>
      </Card>
      <Card class="gap-3 px-4">
        <h2 class="flex items-center gap-2 font-semibold"><Lightbulb class="size-4" /> Insight</h2>
        <div v-for="i in insights" :key="i.title" class="flex gap-3 rounded-lg bg-muted/50 p-3">
          <component :is="i.icon" class="mt-0.5 size-5 shrink-0" :class="i.color" />
          <div>
            <div class="text-sm font-medium">{{ i.title }}</div>
            <div class="text-xs text-muted-foreground">{{ i.text }}</div>
          </div>
        </div>
      </Card>
    </div>
  </main>
</template>
