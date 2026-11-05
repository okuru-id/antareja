import { ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

export type Kind = 'Url' | 'SourcePath'
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
export interface Target { id: string; kind: { type: Kind; value: string }; label: string; owned: boolean; created_at: string; linked: string | null }
export interface Finding {
  id: string; mode: 'Dast' | 'Sast'; tool: string; severity: Severity; title: string; location: string
  description: string; impact: string; recommendation: string; status: Status; rule_id: string | null
  confirmed: string | null; evidence: string
}
export interface Scan { id: string; target_id: string; started_at: string; finished_at: string | null; findings: Finding[]; errors: string[] }

export type Status = 'Open' | 'Fixed' | 'AcceptedRisk' | 'FalsePositive'
export const STATUS_LABEL: Record<Status, string> = {
  Open: 'Open', Fixed: 'Sudah diperbaiki', AcceptedRisk: 'Risiko diterima', FalsePositive: 'False positive',
}

export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
export const sevClass: Record<Severity, string> = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-amber-400 text-black',
  Low: 'bg-sky-500 text-white',
  Info: 'bg-muted text-muted-foreground',
}

/** Tab aktif, folder hasil drag-drop, dan status scan: dibagi antar view. */
export const tab = ref('dashboard')
export const dropped = ref('')
export const progress = ref<Record<string, string>>({}) // target_id -> pesan terakhir; ada = sedang scan

/** Data bersama: daftar target + scan terakhir tiap target (dimuat ulang setiap scan selesai). */
export interface TargetScan { target: Target; scan: Scan }
export interface ScanSummary { id: string; target_id: string; started_at: string; finished_at: string | null; errors: number; open: number[] }
export const targets = ref<Target[]>([])
export const scans = ref<TargetScan[]>([])
export const history = ref<ScanSummary[]>([]) // semua scan, lama -> baru
export async function refresh() {
  ;[targets.value, scans.value, history.value] = await Promise.all([
    invoke<Target[]>('list_targets'), invoke<TargetScan[]>('latest_scans'), invoke<ScanSummary[]>('scan_history'),
  ])
}
/** Temuan Open per severity (urutan SEVERITIES) pada waktu `t`: scan terakhir tiap target sebelum `t`. */
export function postureAt(t: number) {
  const last = new Map<string, ScanSummary>()
  for (const h of history.value) if (new Date(h.started_at).getTime() <= t) last.set(h.target_id, h)
  const sum = [0, 0, 0, 0, 0]
  for (const h of last.values()) h.open.forEach((n, i) => (sum[i] += n))
  return sum
}
/** Akhir hari (23.59) untuk `daysAgo` hari lalu. */
export const endOfDay = (daysAgo: number) => {
  const d = new Date()
  d.setHours(23, 59, 59, 999)
  return d.getTime() - daysAgo * 864e5
}
export const openFindings = (s?: Scan) => s?.findings.filter((f) => f.status === 'Open') ?? []
/** Filter awal tab Temuan saat dibuka dari dashboard. */
export const findingsQuery = ref({ target: 'all', severity: 'all' })
export function showFindings(target = 'all', severity = 'all') {
  findingsQuery.value = { target, severity }
  tab.value = 'findings'
}
export const SEV_COLOR: Record<Severity, string> = {
  Critical: '#dc2626', High: '#f97316', Medium: '#f59e0b', Low: '#3b82f6', Info: '#94a3b8',
}

export function ago(iso: string) {
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000)
  if (m < 1) return 'baru saja'
  if (m < 60) return `${m} menit lalu`
  if (m < 1440) return `${Math.round(m / 60)} jam lalu`
  return `${Math.round(m / 1440)} hari lalu`
}

/** Tema: 'light' | 'dark' disimpan; kosong = ikut OS. */
export const dark = ref(false)
const os = matchMedia('(prefers-color-scheme: dark)')
function applyTheme() {
  let saved = ''
  try { saved = localStorage.getItem('theme') ?? '' } catch {}
  dark.value = saved ? saved === 'dark' : os.matches
  document.documentElement.classList.toggle('dark', dark.value)
}
os.addEventListener('change', applyTheme)
applyTheme()
export function toggleTheme() {
  try { localStorage.setItem('theme', dark.value ? 'light' : 'dark') } catch {}
  applyTheme()
}

/** Log live per target (scan sesi ini); urutan = urutan tab. */
export interface ScanLog { label: string; lines: string[] }
export const logs = ref<Record<string, ScanLog>>({})
export const logTab = ref('') // target_id yang tampil di panel
export const logOpen = ref(false) // panel log kanan
/** Sidebar mini (ikon saja); diingat per perangkat. */
const readMini = () => { try { return localStorage.getItem('sidebarMini') === '1' } catch { return false } }
export const sidebarMini = ref(readMini())
export function toggleSidebar() {
  sidebarMini.value = !sidebarMini.value
  try { localStorage.setItem('sidebarMini', sidebarMini.value ? '1' : '0') } catch {}
}
const stamp = () => new Date().toLocaleTimeString('id-ID')
export const push = (id: string, m: string) => logs.value[id]?.lines.push(`${stamp()}  ${m}`)
/** Log baru di panel kanan (scan target atau update tool); id yang sama menimpa log lama. */
export function startLog(id: string, label: string, first: string) {
  logs.value[id] = { label, lines: [] }
  push(id, first)
  logTab.value = id
  logOpen.value = true
}
listen<{ target_id: string; msg: string }>('scan-progress', ({ payload: p }) => {
  if (p.target_id in progress.value) progress.value[p.target_id] = p.msg
  push(p.target_id, p.msg)
})

/** Info scan terakhir yang dijalankan sesi ini (untuk progres di halaman Scan). */
export interface ScanRun { modules: string[]; mode: string; start: number; end?: number; found?: number; failed?: number; error?: string; stopping?: boolean; stopped?: boolean }
export const runs = ref<Record<string, ScanRun>>({})

/** Minta backend menghentikan scan; runScan lalu selesai dengan error "dihentikan". */
export async function cancelScan(id: string) {
  if (runs.value[id]) runs.value[id]!.stopping = true
  push(id, 'Menghentikan scan…')
  await invoke('cancel_scan', { targetId: id })
}

/** `modules`/`deep` dari halaman Scan; tanpa opsi = semua modul sesuai Pengaturan. */
export async function runScan(t: Target, opts: { modules?: string[]; deep?: boolean; mode?: string } = {}) {
  progress.value[t.id] = 'Memulai…'
  runs.value[t.id] = { modules: opts.modules ?? [], mode: opts.mode ?? 'Standar', start: Date.now() }
  startLog(t.id, t.label, `Scan "${t.label}" dimulai`)
  try {
    const s = await invoke<Scan>('run_scan', { targetId: t.id, modules: opts.modules ?? null, deep: opts.deep ?? false })
    Object.assign(runs.value[t.id]!, { found: s.findings.length, failed: s.errors.length })
    push(t.id, `Selesai: ${s.findings.length} temuan, ${s.errors.length} modul gagal`)
  } catch (e) {
    if (runs.value[t.id]!.stopping) runs.value[t.id]!.stopped = true
    else runs.value[t.id]!.error = String(e)
    push(t.id, `Error: ${e}`)
    throw e
  } finally {
    runs.value[t.id]!.end = Date.now()
    delete progress.value[t.id]
    await refresh()
  }
}
