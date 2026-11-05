<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useIntervalFn } from '@vueuse/core'
import {
  Layers, Zap, Target as TargetIcon, Settings2, ChevronDown, Play, Activity, Globe, FolderOpen, Bug, Clock, CheckCircle2,
  AlertCircle, Loader2, ListChecks, ChevronRight, Square, CircleSlash, Circle, XCircle, Swords, ShieldAlert,
} from '@lucide/vue'
import { invoke } from '@tauri-apps/api/core'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { targets, scans, progress, runs, logs, runScan, cancelScan, showFindings, openFindings, ago, tab, type Target } from './store'

// Modul per jenis target; id = nama scanner di backend, tool = id di tool_info (harus terpasang).
type Mod = { id: string; label: string; desc: string; tool?: string }
const MODULES: Record<'Url' | 'SourcePath' | 'Intrusive', Mod[]> = {
  Url: [
    { id: 'Headers', label: 'Header keamanan', desc: 'CSP, HSTS, cookie, dll.' },
    { id: 'TLS', label: 'TLS / sertifikat', desc: 'Versi protokol & masa berlaku' },
    { id: 'Ports', label: 'Port terbuka', desc: 'Layanan sensitif yang terekspos' },
    { id: 'Files', label: 'File sensitif', desc: '.env, .git, backup, dll.' },
    { id: 'Nuclei', label: 'Nuclei', desc: 'Template CVE, panel, misconfig (+ crawl Katana)', tool: 'nuclei' },
    { id: 'testssl', label: 'testssl.sh', desc: 'TLS mendalam: cipher, Heartbleed, ROBOT', tool: 'testssl' },
    { id: 'Nmap', label: 'nmap', desc: 'Port + versi layanan (menggantikan Ports)', tool: 'nmap' },
    { id: 'ZAP', label: 'OWASP ZAP baseline', desc: 'Spider + passive scan', tool: 'zap' },
    { id: 'Observatory', label: 'Mozilla Observatory', desc: 'Layanan online; aktifkan di Pengaturan' },
  ],
  SourcePath: [
    { id: 'Gitleaks', label: 'Gitleaks', desc: 'Secret di kode & riwayat git', tool: 'gitleaks' },
    { id: 'Trivy', label: 'Trivy', desc: 'CVE, misconfig IaC, lisensi', tool: 'trivy' },
    { id: 'Semgrep', label: 'Semgrep', desc: 'Bug & pola kode rawan', tool: 'semgrep' },
  ],
  Intrusive: [
    { id: 'sqlmap', label: 'sqlmap', desc: 'SQL injection (crawl + form)', tool: 'sqlmap' },
    { id: 'dalfox', label: 'dalfox', desc: 'XSS pada parameter URL', tool: 'dalfox' },
    { id: 'ffuf', label: 'ffuf', desc: 'Path tersembunyi (wordlist ringkas)', tool: 'ffuf' },
    { id: 'ZAP-active', label: 'ZAP active scan', desc: 'Serangan aktif ZAP (maks. 15 menit)', tool: 'zap' },
  ],
}

type Mode = 'quick' | 'standard' | 'full' | 'intrusive'
type K = 'Url' | 'SourcePath'
const MODES: Record<Mode, { label: string; icon: unknown; desc: Record<K, string>; time: Record<K, string> }> = {
  quick: { label: 'Quick Scan', icon: Zap,
    desc: { Url: 'Header & TLS saja', SourcePath: 'Secret & dependency' },
    time: { Url: '± 10 detik', SourcePath: '< 1 menit' } },
  standard: { label: 'Standard Scan', icon: Layers,
    desc: { Url: 'Semua modul bawaan', SourcePath: 'Semua tool, sesuai Pengaturan' },
    time: { Url: '± 1 menit', SourcePath: '± 1–3 menit' } },
  full: { label: 'Full Scan', icon: TargetIcon,
    desc: { Url: 'Plus Nuclei, testssl, nmap, ZAP', SourcePath: 'Plus riwayat git & rule OWASP' },
    time: { Url: '± 5–30 menit', SourcePath: '± 3–10 menit' } },
  intrusive: { label: 'Intrusive Scan', icon: Swords,
    desc: { Url: 'SQLi, XSS, fuzzing, ZAP active', SourcePath: '' },
    time: { Url: '± 5–30 menit', SourcePath: '' } },
}

// Status tool terpasang + pengaturan yang memengaruhi pilihan modul.
const online = ref(false)
const installed = ref<Set<string>>(new Set())
const allowHosts = ref<string[]>([])
invoke<{ online: boolean }>('get_dast_options').then((o) => (online.value = o.online)).catch(() => {})
invoke<{ id: string; version: string | null }[]>('tool_info').then((ts) => (installed.value = new Set(ts.filter((t) => t.version).map((t) => t.id)))).catch(() => {})
invoke<{ intrusive_hosts: string[] }>('get_tool_options').then((o) => (allowHosts.value = o.intrusive_hosts)).catch(() => {})

// Target terpilih: default aktivitas terbaru.
const latestOf = (t: Target) => scans.value.find((d) => d.target.id === t.id)?.scan
const pickId = ref('')
watch(targets, (ts) => {
  if (ts.some((t) => t.id === pickId.value)) return
  const when = (t: Target) => latestOf(t)?.started_at ?? t.created_at
  pickId.value = [...ts].sort((a, b) => (when(a) < when(b) ? 1 : -1))[0]?.id ?? ''
}, { immediate: true })
const target = computed(() => targets.value.find((t) => t.id === pickId.value))
const kind = computed<K>(() => target.value?.kind.type ?? 'Url')
const last = computed(() => target.value && latestOf(target.value))
const open = computed(() => openFindings(last.value))
const crit = computed(() => open.value.filter((f) => f.severity === 'Critical').length)

// Sama dengan aturan backend (intrusive::host_allowed); backend tetap memeriksa ulang.
const hostAllowed = computed(() => {
  if (kind.value !== 'Url' || !target.value) return false
  let h = ''
  try { h = new URL(target.value.kind.value).hostname.toLowerCase().replace(/^\[|\]$/g, '') } catch { return false }
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.test') || h === '::1' || /^127\.\d+\.\d+\.\d+$/.test(h)) return true
  return allowHosts.value.map((d) => d.trim().toLowerCase()).filter(Boolean)
    .some((d) => (d.startsWith('*.') ? h.endsWith(d.slice(1)) : h === d))
})
const modesFor = computed(() => (Object.keys(MODES) as Mode[]).filter((m) => m !== 'intrusive' || kind.value === 'Url'))

const mode = ref<Mode>('standard')
const confirmIntrusive = ref(false)
watch([kind, hostAllowed], () => {
  if (mode.value === 'intrusive' && !hostAllowed.value) mode.value = 'standard'
})
watch([mode, pickId], () => (confirmIntrusive.value = false))
const showAdv = ref(false)
const modules = computed(() => MODULES[mode.value === 'intrusive' ? 'Intrusive' : kind.value])
const avail = (m: Mod) => (m.id === 'Observatory' ? online.value : !m.tool || installed.value.has(m.tool))
const preset = (m: Mode, k: K) => {
  const ids = (list: Mod[]) => list.filter(avail).map((x) => x.id)
  if (m === 'intrusive') return ids(MODULES.Intrusive)
  const all = ids(MODULES[k])
  if (k === 'SourcePath') return m === 'quick' ? ['Gitleaks', 'Trivy'] : all
  const builtin = ['Headers', 'TLS', 'Ports', 'Files', ...(online.value ? ['Observatory'] : [])]
  if (m === 'quick') return ['Headers', 'TLS']
  if (m === 'standard') return builtin
  // Full: semua yang terpasang; nmap menggantikan modul Ports.
  return all.includes('Nmap') ? all.filter((x) => x !== 'Ports') : all
}
const chosen = ref<string[]>([])
watch([mode, kind, online, installed], () => (chosen.value = preset(mode.value, kind.value)), { immediate: true })
const toggle = (id: string, on: boolean) => (chosen.value = on ? [...chosen.value, id] : chosen.value.filter((x) => x !== id))
const custom = computed(() => [...chosen.value].sort().join() !== [...preset(mode.value, kind.value)].sort().join())

const running = computed(() => !!target.value && target.value.id in progress.value)
async function start() {
  const t = target.value
  if (!t || running.value || !chosen.value.length || (mode.value === 'intrusive' && !confirmIntrusive.value)) return
  // Urutan modul mengikuti daftar agar progres konsisten.
  const mods = modules.value.map((m) => m.id as string).filter((id) => chosen.value.includes(id))
  try {
    await runScan(t, { modules: mods, deep: mode.value === 'full', mode: MODES[mode.value].label + (custom.value ? ' (kustom)' : '') })
  } catch { /* error tampil di kartu progres & panel log */ }
}

// Progres dihitung dari log modul: "X berjalan…", "X selesai: N temuan", "X gagal".
const run = computed(() => (target.value ? runs.value[target.value.id] : undefined))
const lines = computed(() => (target.value ? logs.value[target.value.id]?.lines ?? [] : []))
type ModState = { state: 'wait' | 'run' | 'done' | 'fail'; found?: number }
const stat = computed(() => {
  const st: Record<string, ModState> = {}
  for (const l of lines.value) {
    const m = l.match(/^\S+\s{2}(\S+) (berjalan…|selesai: (\d+) temuan|gagal)/)
    if (!m) continue
    st[m[1]!] = m[2] === 'berjalan…' ? { state: 'run' } : m[3] ? { state: 'done', found: Number(m[3]) } : { state: 'fail' }
  }
  const ids = run.value?.modules.length ? run.value.modules : Object.keys(st)
  // Scan sudah berakhir (dihentikan/gagal): modul yang belum selesai tidak lagi "berjalan".
  const ended = !!run.value?.end
  const list = ids.map((id) => {
    const m = st[id] ?? { state: 'wait' as const }
    return { id, ...(ended && m.state === 'run' ? { state: 'wait' as const } : m) }
  })
  const done = list.filter((m) => m.state === 'done' || m.state === 'fail')
  return {
    list, total: list.length || 1, done: done.length,
    found: list.reduce((n, m) => n + (m.found ?? 0), 0),
    failed: list.filter((m) => m.state === 'fail').length,
  }
})
const phase = computed(() => {
  const r = run.value
  if (!r) return 'idle'
  if (!r.end) return r.stopping ? 'stopping' : 'running'
  return r.stopped ? 'stopped' : r.error ? 'error' : 'done'
})
const pct = computed(() => (phase.value === 'done' ? 100 : Math.min(99, Math.round((stat.value.done / stat.value.total) * 100))))
const now = ref(Date.now())
useIntervalFn(() => (now.value = Date.now()), 1000)
const elapsed = computed(() => {
  if (!run.value) return '00:00'
  const s = Math.max(0, Math.round(((run.value.end ?? now.value) - run.value.start) / 1000))
  return [Math.floor(s / 3600), Math.floor(s / 60) % 60, s % 60].map((n) => String(n).padStart(2, '0')).join(':').replace(/^00:/, '')
})
const labelOf = (id: string) => [...MODULES.Url, ...MODULES.SourcePath, ...MODULES.Intrusive].find((m) => m.id === id)?.label ?? id
</script>

<template>
  <main class="w-full space-y-4 px-6 pb-6">
    <div class="grid gap-4 @4xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <!-- Pilih target -->
      <Card class="gap-4 px-5">
        <h2 class="flex items-center gap-2 font-semibold"><Layers class="size-4.5 text-muted-foreground" /> Pilih target</h2>
        <p v-if="!targets.length" class="text-sm text-muted-foreground">
          Belum ada target. <button class="text-primary underline" @click="tab = 'targets'">Tambahkan target</button> dulu.
        </p>
        <template v-else>
          <Select v-model="pickId">
            <SelectTrigger class="h-10 w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="t in targets" :key="t.id" :value="t.id">{{ t.kind.type === 'Url' ? 'DAST' : 'SAST' }} · {{ t.label }}</SelectItem>
            </SelectContent>
          </Select>

          <div v-if="target" class="rounded-lg border bg-muted/30">
            <div class="flex items-center gap-3 border-b p-3.5">
              <span class="grid size-10 shrink-0 place-items-center rounded-full bg-card ring-1 ring-border">
                <component :is="kind === 'Url' ? Globe : FolderOpen" class="size-5 text-muted-foreground" />
              </span>
              <div class="min-w-0">
                <div class="truncate font-medium">{{ target.label }}</div>
                <div class="truncate text-xs text-muted-foreground">{{ target.kind.value }}</div>
              </div>
            </div>
            <dl class="divide-y text-sm">
              <div class="flex justify-between gap-3 px-3.5 py-2"><dt class="text-muted-foreground">Jenis</dt><dd>{{ kind === 'Url' ? 'DAST (web)' : 'SAST (source code)' }}</dd></div>
              <div class="flex justify-between gap-3 px-3.5 py-2">
                <dt class="text-muted-foreground">Scan terakhir</dt>
                <dd :title="last ? ago(last.started_at) : undefined">{{ last ? new Date(last.started_at).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' }) : 'Belum pernah' }}</dd>
              </div>
              <div class="flex justify-between gap-3 px-3.5 py-2">
                <dt class="text-muted-foreground">Temuan terbuka</dt>
                <dd class="tabular-nums">
                  {{ last ? open.length : '–' }}
                  <span v-if="crit" class="text-red-600 dark:text-red-500">({{ crit }} Critical)</span>
                </dd>
              </div>
            </dl>
          </div>
        </template>
      </Card>

      <!-- Konfigurasi -->
      <Card class="gap-4 px-5">
        <h2 class="flex items-center gap-2 font-semibold"><Settings2 class="size-4.5 text-muted-foreground" /> Konfigurasi pemindaian</h2>
        <div role="radiogroup" aria-label="Mode" class="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-3">
          <button v-for="key in modesFor" :key="key" role="radio" :aria-checked="mode === key"
            :disabled="key === 'intrusive' && !hostAllowed"
            :title="key === 'intrusive' && !hostAllowed ? 'Hanya untuk localhost atau domain dev yang diizinkan di Pengaturan' : undefined"
            class="group relative rounded-lg border p-3.5 text-left transition-all duration-200 enabled:motion-safe:hover:-translate-y-0.5 enabled:hover:shadow-md enabled:active:translate-y-0 enabled:active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
            :class="mode === key
              ? (key === 'intrusive' ? 'border-red-500 bg-red-500/5 shadow-sm ring-1 ring-red-500' : 'border-primary bg-primary/5 shadow-sm ring-1 ring-primary')
              : 'enabled:hover:border-foreground/20'" @click="mode = key">
            <span class="absolute top-3 right-3 grid size-4 place-items-center rounded-full border transition-colors"
              :class="mode === key ? (key === 'intrusive' ? 'border-red-500' : 'border-primary') : 'border-muted-foreground/40'">
              <span class="size-2 rounded-full transition-transform duration-200" :class="[key === 'intrusive' ? 'bg-red-500' : 'bg-primary', mode === key ? 'scale-100' : 'scale-0']" />
            </span>
            <component :is="MODES[key].icon" class="size-5 transition-all duration-300 motion-safe:group-enabled:group-hover:scale-110"
              :class="mode === key ? (key === 'intrusive' ? 'text-red-500 motion-safe:scale-110' : 'text-primary motion-safe:scale-110') : key === 'intrusive' ? 'text-red-500/70' : 'text-muted-foreground'" />
            <div class="mt-2 text-sm font-semibold">{{ MODES[key].label }}</div>
            <div class="mt-0.5 text-xs text-muted-foreground">{{ key === 'intrusive' && !hostAllowed ? 'Hanya localhost / domain dev yang diizinkan' : MODES[key].desc[kind] }}</div>
            <div class="text-xs text-muted-foreground">({{ MODES[key].time[kind] }})</div>
          </button>
        </div>

        <!-- Konfirmasi wajib sebelum scan intrusif -->
        <Transition enter-from-class="opacity-0 -translate-y-1" enter-active-class="transition duration-200" leave-to-class="opacity-0" leave-active-class="transition duration-150">
          <label v-if="mode === 'intrusive'" class="flex items-start gap-3 rounded-lg border border-red-500/40 bg-red-500/5 p-3.5 text-sm">
            <ShieldAlert class="mt-0.5 size-5 shrink-0 text-red-500" />
            <span class="min-w-0 flex-1">
              <span class="block font-medium">Scan ini mengirim payload serangan sungguhan</span>
              <span class="block text-xs text-muted-foreground">sqlmap, dalfox, ffuf, dan ZAP active bisa menambah, mengubah, atau menghapus data. Jalankan hanya pada lingkungan dev/uji milik sendiri dengan data yang boleh rusak.</span>
              <span class="mt-2 flex items-center gap-2 text-xs font-medium">
                <Checkbox v-model="confirmIntrusive" /> Saya pemilik aplikasi ini dan paham risikonya
              </span>
            </span>
          </label>
        </Transition>

        <div class="rounded-lg border">
          <button class="flex w-full items-center gap-3 p-3.5 text-left" :aria-expanded="showAdv" @click="showAdv = !showAdv">
            <ListChecks class="size-5 shrink-0 text-muted-foreground" />
            <span class="min-w-0 flex-1">
              <span class="block text-sm font-medium">Opsi lanjutan <span v-if="custom" class="ml-1 rounded bg-primary/10 px-1.5 text-[11px] font-semibold text-primary">kustom</span></span>
              <span class="block text-xs text-muted-foreground">Pilih modul yang dijalankan: {{ chosen.length }} dari {{ modules.length }}</span>
            </span>
            <ChevronDown class="size-4 text-muted-foreground transition-transform duration-300" :class="showAdv && 'rotate-180'" />
          </button>
          <div class="grid transition-[grid-template-rows] duration-300 ease-out" :class="showAdv ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'">
          <div class="overflow-hidden" :inert="!showAdv">
          <div class="grid gap-x-4 gap-y-3 border-t p-3.5 transition-opacity duration-300 sm:grid-cols-2" :class="showAdv ? 'opacity-100' : 'opacity-0'">
            <label v-for="m in modules" :key="m.id" class="flex items-start gap-2.5 text-sm" :class="!avail(m) && 'opacity-50'">
              <Checkbox class="mt-0.5" :model-value="chosen.includes(m.id)" :disabled="!avail(m)" @update:model-value="(v) => toggle(m.id, !!v)" />
              <span>
                <span class="block font-medium">{{ m.label }}</span>
                <span class="block text-xs text-muted-foreground">{{ !avail(m) && m.tool ? 'Belum terpasang: pasang di Pengaturan' : m.desc }}</span>
              </span>
            </label>
            <p v-if="mode === 'full'" class="text-xs text-muted-foreground sm:col-span-2">
              Full Scan: {{ kind === 'Url' ? 'semua modul yang terpasang ikut, walau mati di Pengaturan; nmap menggantikan Ports.' : 'riwayat git selalu dipindai dan rule pack p/owasp-top-ten + p/security-audit ditambahkan.' }}
            </p>
          </div>
          </div>
          </div>
        </div>
      </Card>
    </div>

    <Card class="px-5 py-4">
      <div class="flex flex-wrap items-center gap-3">
        <Button size="lg" class="group min-w-56 flex-1 transition-all motion-safe:hover:shadow-lg motion-safe:hover:shadow-primary/25 active:scale-[0.99]" :disabled="!target || running || !chosen.length || (mode === 'intrusive' && !confirmIntrusive)" @click="start"
          :class="mode === 'intrusive' && 'bg-red-600 hover:bg-red-600/90 motion-safe:hover:shadow-red-600/25'">
          <Loader2 v-if="running" class="animate-spin" /><Play v-else class="transition-transform motion-safe:group-hover:translate-x-0.5" /> {{ running ? 'Sedang memindai…' : 'Mulai pemindaian' }}
        </Button>
        <span class="text-xs text-muted-foreground">Hanya untuk target milik sendiri. Progres detail ada di panel log.</span>
      </div>
    </Card>

    <!-- Progres -->
    <Transition enter-from-class="opacity-0 translate-y-3" enter-active-class="transition duration-300 ease-out">
    <Card v-if="run" class="gap-4 px-5">
      <h2 class="flex items-center gap-2 font-semibold"><Activity class="size-4.5 text-muted-foreground" :class="phase === 'running' && 'motion-safe:animate-pulse text-primary'" /> Progres pemindaian</h2>
      <div class="grid items-center gap-5 @4xl:grid-cols-[auto_minmax(0,1fr)_280px]">
        <!-- Cincin: sudut dianimasikan lewat @property --p; berdenyut selama berjalan -->
        <div class="relative grid size-28 place-items-center">
          <!-- Berjalan/menghentikan: radar menyapu. Selesai/dihentikan/gagal: cincin + ikon. -->
          <div v-if="phase === 'running' || phase === 'stopping'" class="radar relative size-28 overflow-hidden rounded-full border border-current/25" :class="phase === 'stopping' && 'stopping'">
            <span class="absolute inset-[16%] rounded-full border border-current/15" />
            <span class="absolute inset-[34%] rounded-full border border-current/15" />
            <span class="absolute top-0 bottom-0 left-1/2 w-px -translate-x-1/2 bg-current/10" />
            <span class="absolute right-0 left-0 top-1/2 h-px -translate-y-1/2 bg-current/10" />
            <span class="radar-sweep absolute inset-0 rounded-full motion-reduce:hidden" />
            <span class="absolute inset-0 grid place-items-center text-xl font-semibold tabular-nums text-foreground">{{ pct }}%</span>
          </div>
          <div v-else class="ring-p relative grid size-28 place-items-center rounded-full" :class="`ring-${phase}`" :style="{ '--p': pct }">
            <span class="grid size-[5.5rem] place-items-center rounded-full bg-card">
              <CheckCircle2 v-if="phase === 'done'" class="pop size-10 text-green-600" />
              <CircleSlash v-else-if="phase === 'stopped'" class="pop size-10 text-amber-500" />
              <XCircle v-else-if="phase === 'error'" class="pop size-10 text-destructive" />
              <span v-else class="text-2xl font-semibold tabular-nums">{{ pct }}%</span>
            </span>
          </div>
        </div>
        <div class="min-w-0 space-y-2.5">
          <div class="truncate text-lg font-semibold">
            {{ { running: 'Memindai', stopping: 'Menghentikan', done: 'Scan selesai', stopped: 'Scan dihentikan', error: 'Scan gagal', idle: '' }[phase] }} {{ target?.label }}
          </div>
          <p class="text-sm text-muted-foreground">{{ run.mode }} · {{ stat.done }} dari {{ stat.total }} modul selesai</p>
          <div class="h-2 overflow-hidden rounded-full bg-muted">
            <div class="relative h-full overflow-hidden rounded-full transition-[width] duration-700 ease-out"
              :class="{ 'bg-primary': phase === 'running' || phase === 'done', 'bg-amber-500': phase === 'stopping' || phase === 'stopped', 'bg-destructive': phase === 'error' }"
              :style="{ width: Math.max(pct, phase === 'running' ? 4 : 0) + '%' }">
              <span v-if="phase === 'running'" class="shimmer absolute inset-0" />
            </div>
          </div>
          <!-- Daftar modul: menunggu -> berjalan -> selesai/gagal -->
          <TransitionGroup tag="ul" class="flex flex-wrap gap-1.5" enter-from-class="opacity-0 scale-90" enter-active-class="transition duration-200">
            <li v-for="m in stat.list" :key="m.id" class="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors duration-300"
              :class="{
                'text-muted-foreground': m.state === 'wait',
                'border-primary/40 bg-primary/5 text-primary': m.state === 'run',
                'border-green-600/30 bg-green-600/5 text-green-700 dark:text-green-400': m.state === 'done',
                'border-destructive/30 bg-destructive/5 text-destructive': m.state === 'fail',
              }">
              <Loader2 v-if="m.state === 'run'" class="size-3.5 animate-spin" />
              <CheckCircle2 v-else-if="m.state === 'done'" class="pop size-3.5" />
              <XCircle v-else-if="m.state === 'fail'" class="pop size-3.5" />
              <Circle v-else class="size-3.5 opacity-40" />
              {{ labelOf(m.id) }}
              <span v-if="m.found !== undefined" class="tabular-nums opacity-70">· {{ m.found }}</span>
            </li>
          </TransitionGroup>
          <p v-if="run.error" class="text-sm break-words text-destructive">{{ run.error }}</p>
          <p v-else-if="phase === 'stopped'" class="text-sm text-muted-foreground">Hasil scan ini dibuang; data scan sebelumnya tetap dipakai.</p>
          <Button v-else-if="phase === 'done'" size="sm" variant="outline" class="pop" @click="showFindings(target!.id)">Lihat temuan <ChevronRight /></Button>
        </div>
        <div class="space-y-3">
          <dl class="divide-y rounded-lg border text-sm">
            <div class="flex items-center gap-2.5 px-3.5 py-2.5"><ListChecks class="size-4 text-muted-foreground" /><dt class="flex-1">Modul selesai</dt><dd class="font-semibold tabular-nums">{{ stat.done }}/{{ stat.total }}</dd></div>
            <div class="flex items-center gap-2.5 px-3.5 py-2.5"><Bug class="size-4 text-muted-foreground" /><dt class="flex-1">Temuan ditemukan</dt>
              <dd :key="run.found ?? stat.found" class="pop font-semibold tabular-nums">{{ run.found ?? stat.found }}</dd></div>
            <div class="flex items-center gap-2.5 px-3.5 py-2.5"><Clock class="size-4 text-muted-foreground" /><dt class="flex-1">Durasi</dt><dd class="font-semibold tabular-nums">{{ elapsed }}</dd></div>
            <div v-if="stat.failed" class="flex items-center gap-2.5 px-3.5 py-2.5 text-amber-600 dark:text-amber-400"><AlertCircle class="size-4" /><dt class="flex-1">Modul gagal</dt><dd class="font-semibold tabular-nums">{{ stat.failed }}</dd></div>
          </dl>
          <Button v-if="phase === 'running' || phase === 'stopping'" variant="outline" class="w-full border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
            :disabled="phase === 'stopping'" @click="cancelScan(target!.id)">
            <Loader2 v-if="phase === 'stopping'" class="animate-spin" /><Square v-else class="fill-current" />
            {{ phase === 'stopping' ? 'Menghentikan…' : 'Hentikan scan' }}
          </Button>
        </div>
      </div>
    </Card>
    </Transition>
  </main>
</template>

<style scoped>
/* Sudut cincin bisa ditransisikan berkat @property. */
@property --p { syntax: '<number>'; inherits: false; initial-value: 0; }
.ring-p {
  --c: var(--primary);
  background: conic-gradient(var(--c) calc(var(--p) * 1%), var(--muted) 0);
  transition: --p 0.7s ease-out;
}
.ring-done { --c: #16a34a; }
.ring-stopping, .ring-stopped { --c: #f59e0b; }
.ring-error { --c: var(--destructive); }
.shimmer {
  background: linear-gradient(90deg, transparent, rgb(255 255 255 / 0.45), transparent);
  animation: shimmer 1.4s ease-in-out infinite;
}
@keyframes shimmer { from { transform: translateX(-100%); } to { transform: translateX(100%); } }
.pop { animation: pop 0.35s cubic-bezier(0.34, 1.56, 0.64, 1); }
@keyframes pop { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }
/* Radar: warna sapuan & grid mengikuti --rc (biru saat berjalan, amber saat menghentikan). */
.radar { --rc: var(--primary); color: var(--rc); }
.radar.stopping { --rc: #f59e0b; }
.radar-sweep {
  background: conic-gradient(from 0deg, transparent 0 300deg, var(--rc) 360deg);
  animation: radar-spin 1.8s linear infinite;
  transform-origin: center;
}
@keyframes radar-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .ring-p { transition: none; }
  .shimmer, .pop { animation: none; }
}
</style>
