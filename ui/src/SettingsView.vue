<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useDebounceFn } from '@vueuse/core'
import { invoke } from '@tauri-apps/api/core'
import { RefreshCw, Download, Loader2, CheckCircle2, AlertCircle, ArrowUpCircle, Search, SearchX, X } from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Card } from '@/components/ui/card'
import { push, startLog } from './store'

interface ToolInfo { id: string; version: string | null; data: string | null; source: 'update' | 'bawaan' | 'sistem' }
interface ToolOptions {
  semgrep_extra: string[]; semgrep_exclude: string[]; gitleaks_history: boolean
  trivy_ignore_unfixed: boolean; trivy_misconfig: boolean; trivy_license: boolean
  nuclei_tags: string; nuclei_rate: number; nuclei_crawl: boolean; intrusive_hosts: string[]; intrusive_rate: number
}

type Mode = 'SAST' | 'DAST' | 'Intrusif'
const TOOLS: { id: string; name: string; mode: Mode; desc: string; actions: { key: string; label: string }[]; hint?: string; system?: boolean }[] = [
  { id: 'semgrep', name: 'Semgrep', mode: 'SAST', desc: 'Analisis pola kode rawan. Rule diambil dari registry Semgrep setiap scan, jadi selalu terbaru.',
    actions: [{ key: 'semgrep', label: 'Update program' }] },
  { id: 'gitleaks', name: 'Gitleaks', mode: 'SAST', desc: 'Deteksi secret di file dan riwayat git. Rule tertanam di program: update program untuk pola secret terbaru.',
    actions: [{ key: 'gitleaks', label: 'Update program' }] },
  { id: 'trivy', name: 'Trivy', mode: 'SAST', desc: 'CVE dependency, salah konfigurasi IaC (Dockerfile, Kubernetes, Terraform), dan lisensi berisiko. Database CVE juga diperbarui otomatis saat scan bila sudah lewat 24 jam.',
    actions: [{ key: 'trivy-db', label: 'Update database CVE' }, { key: 'trivy', label: 'Update program' }] },
  { id: 'nuclei', name: 'Nuclei', mode: 'DAST', desc: 'Template komunitas untuk CVE, panel, dan misconfig. Template intrusif, brute-force, dan OAST selalu dikecualikan.',
    actions: [{ key: 'nuclei-templates', label: 'Update template' }, { key: 'nuclei', label: 'Update program' }] },
  { id: 'katana', name: 'Katana', mode: 'DAST', desc: 'Crawler: menemukan endpoint dari link, form, dan JavaScript, lalu dipakai Nuclei dan dalfox agar cakupan lebih luas.',
    actions: [{ key: 'katana', label: 'Update program' }] },
  { id: 'testssl', name: 'testssl.sh', mode: 'DAST', desc: 'Analisis TLS mendalam: protokol & cipher lemah, Heartbleed, ROBOT, rantai sertifikat. Versi dipin dan diverifikasi checksum. Butuh bash (Linux/macOS).',
    actions: [{ key: 'testssl', label: 'Update program' }] },
  { id: 'nmap', name: 'nmap', mode: 'DAST', desc: 'Port terbuka + versi layanan (pengganti modul Ports bawaan di mode Full). Dipasang dari repo resmi OS lewat package manager sistem (lisensinya tidak mengizinkan dibundel).',
    actions: [{ key: 'nmap', label: 'Update program' }], hint: 'Pakai package manager sistem (butuh izin admin). Alternatif: installer dari nmap.org.', system: true },
  { id: 'zap', name: 'OWASP ZAP', mode: 'DAST', desc: 'Baseline: spider + passive scan (cookie, CSP, info leak, dll.), tidak menyerang. Unduhan ±250 MB; JRE 17 ikut dipasang bila Java sistem belum ada.',
    actions: [{ key: 'zap', label: 'Update program' }] },
  { id: 'sqlmap', name: 'sqlmap', mode: 'Intrusif', desc: 'Deteksi SQL injection dengan payload nyata (crawl 2 tingkat + form, level/risk terendah). Bisa mengubah data.',
    actions: [{ key: 'sqlmap', label: 'Update program' }] },
  { id: 'dalfox', name: 'dalfox', mode: 'Intrusif', desc: 'Deteksi XSS dengan payload pada parameter URL (dari crawl Katana bila terpasang).',
    actions: [{ key: 'dalfox', label: 'Update program' }] },
  { id: 'ffuf', name: 'ffuf', mode: 'Intrusif', desc: 'Mencari path tersembunyi (backup, .env, panel admin) dengan wordlist ringkas ±130 path.',
    actions: [{ key: 'ffuf', label: 'Update program' }] },
]
const MODE_CLS: Record<Mode, string> = {
  SAST: 'bg-primary/10 text-primary',
  DAST: 'bg-violet-500/10 text-violet-600 dark:text-violet-400',
  Intrusif: 'bg-red-500/10 text-red-600 dark:text-red-400',
}
const TRIVY_OPTS = [
  { k: 'trivy_misconfig', label: 'Cek salah konfigurasi IaC', desc: 'Dockerfile, Kubernetes, Terraform, Docker Compose, CloudFormation.' },
  { k: 'trivy_license', label: 'Cek lisensi berisiko', desc: 'Hanya lisensi kategori terlarang/copyleft kuat (mis. AGPL, GPL) yang dilaporkan.' },
  { k: 'trivy_ignore_unfixed', label: 'Abaikan CVE tanpa perbaikan', desc: 'Hanya tampilkan CVE yang sudah ada versi perbaikannya.' },
] as const
const SOURCE = { update: 'hasil update', bawaan: 'bawaan aplikasi', sistem: 'dari sistem (PATH)' }

const info = ref<Record<string, ToolInfo>>({})
// Versi terbaru yang dirilis; '' = gagal cek (mis. offline).
const latest = ref<Record<string, string>>({})
const busy = ref<Record<string, boolean>>({})
const result = ref<Record<string, { ok: boolean; text: string }>>({})
const dast = ref({ nuclei: false, online: false, testssl: false, nmap: false, zap: false })
const opts = ref<ToolOptions>({
  semgrep_extra: [], semgrep_exclude: [], gitleaks_history: true, trivy_ignore_unfixed: false, trivy_misconfig: true, trivy_license: true,
  nuclei_tags: '', nuclei_rate: 50, nuclei_crawl: true, intrusive_hosts: [], intrusive_rate: 20,
})
// Daftar diedit sebagai teks dipisah koma.
const extra = ref('')
const exclude = ref('')
const hosts = ref('')
const loading = ref(false)

// Cari/filter kartu tool berdasarkan nama, mode, atau deskripsi.
const q = ref('')
const filtered = computed(() => {
  const s = q.value.trim().toLowerCase()
  if (!s) return TOOLS
  return TOOLS.filter((t) => `${t.name} ${t.mode} ${t.desc}`.toLowerCase().includes(s))
})
// Tool terverifikasi (centang hijau): versi terbaca DAN salah satu —
// dipasang via updater app (checksum SHA-256 dicek) / bawaan app / tool sistem terpasang (nmap) / terkonfirmasi versi terbaru.
// Jadi centang tetap muncul walau cek versi ke GitHub gagal (mis. rate limit).
const valid = (t: { id: string; system?: boolean }) => {
  const i = info.value[t.id]
  return !!i?.version && (t.system || i.source === 'update' || i.source === 'bawaan' || latest.value[t.id] === i.version)
}

const list = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
const saveDast = () => invoke('set_dast_options', { options: dast.value })
// Simpan otomatis setelah berhenti mengetik; batas rate juga dijaga di backend.
const saveOpts = useDebounceFn(() => invoke('set_tool_options', { options: {
  ...opts.value,
  semgrep_extra: list(extra.value),
  semgrep_exclude: list(exclude.value),
  nuclei_rate: Math.min(500, Math.max(1, Math.round(Number(opts.value.nuclei_rate) || 50))),
  intrusive_hosts: list(hosts.value),
  intrusive_rate: Math.min(500, Math.max(1, Math.round(Number(opts.value.intrusive_rate) || 20))),
} }), 400)
let loaded = false
watch([opts, extra, exclude, hosts], () => loaded && saveOpts(), { deep: true })

async function loadInfo() {
  loading.value = true
  try {
    const [infos] = await Promise.all([
      invoke<ToolInfo[]>('tool_info'),
      ...TOOLS.map(async (t) => (latest.value[t.id] = await invoke<string>('tool_latest', { id: t.id }).catch(() => ''))),
    ])
    info.value = Object.fromEntries((infos as ToolInfo[]).map((t) => [t.id, t]))
  } finally {
    loading.value = false
  }
}

async function update(tool: string, key: string, label: string) {
  busy.value[key] = true
  delete result.value[tool]
  const id = `update-${key}`
  startLog(id, `${label}`, `${label} dimulai`)
  try {
    const msg = await invoke<string>('update_tool', { tool: key })
    result.value[tool] = { ok: true, text: msg }
    push(id, msg)
  } catch (e) {
    result.value[tool] = { ok: false, text: String(e) }
    push(id, `Error: ${e}`)
  } finally {
    busy.value[key] = false
    await loadInfo()
  }
}

onMounted(async () => {
  dast.value = await invoke('get_dast_options')
  opts.value = await invoke('get_tool_options')
  extra.value = opts.value.semgrep_extra.join(', ')
  exclude.value = opts.value.semgrep_exclude.join(', ')
  hosts.value = opts.value.intrusive_hosts.join(', ')
  loaded = true
  await loadInfo()
})
</script>

<template>
  <main class="w-full space-y-4 px-6 pb-6">
    <div class="flex flex-wrap items-center gap-2">
      <h2 class="font-semibold">Tool scan</h2>
      <span class="text-sm text-muted-foreground">Program diunduh dari rilis resmi GitHub dan checksum SHA-256-nya diverifikasi sebelum dipasang.</span>
      <Button variant="outline" size="sm" class="ml-auto" :disabled="loading" @click="loadInfo">
        <RefreshCw :class="loading && 'animate-spin'" /> Cek versi
      </Button>
    </div>

    <div class="relative max-w-sm">
      <Search class="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input v-model="q" placeholder="Cari tool…" aria-label="Cari tool"
        class="h-9 rounded-full border-border bg-card pr-9 pl-9 focus-visible:border-ring" />
      <button v-if="q" type="button" aria-label="Hapus pencarian" @click="q = ''"
        class="absolute top-1/2 right-2.5 grid size-5 -translate-y-1/2 place-items-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">
        <X class="size-3.5" />
      </button>
    </div>

    <div v-if="!filtered.length" class="flex flex-col items-center gap-2 rounded-xl border border-dashed py-12 text-sm text-muted-foreground">
      <SearchX class="size-6 opacity-60" /> Tidak ada tool cocok dengan “{{ q }}”.
    </div>

    <div v-else class="grid grid-cols-[repeat(auto-fill,minmax(min(100%,420px),1fr))] gap-4">
      <Card v-for="t in filtered" :key="t.id" class="gap-4 px-5">
        <div class="flex flex-wrap items-start gap-x-3 gap-y-1">
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <h3 class="font-semibold">{{ t.name }}</h3>
              <span class="rounded-md px-1.5 py-0.5 text-[11px] font-semibold" :class="MODE_CLS[t.mode]">{{ t.mode }}</span>
            </div>
            <p class="mt-1 text-sm text-muted-foreground">{{ t.desc }}</p>
          </div>
          <div class="text-right text-sm">
            <div v-if="info[t.id]?.version" class="flex items-center justify-end gap-1.5 font-mono font-medium">
              <CheckCircle2 v-if="valid(t)" class="size-4 text-green-600 dark:text-green-500" />
              v{{ info[t.id]!.version }}
              <span v-if="valid(t)" class="sr-only">(terverifikasi)</span>
            </div>
            <div v-else-if="info[t.id]" class="font-medium text-destructive">Tidak ditemukan</div>
            <div v-else class="text-muted-foreground">…</div>
            <div v-if="info[t.id]?.version" class="text-xs text-muted-foreground">
              <template v-if="t.system">Terpasang · </template>
              <template v-else-if="latest[t.id] === info[t.id]!.version">Versi terbaru · </template>{{ SOURCE[info[t.id]!.source] }}
            </div>
            <div v-if="latest[t.id] && info[t.id]?.version && latest[t.id] !== info[t.id]?.version" class="mt-0.5 flex items-center justify-end gap-1 text-xs font-medium text-amber-600 dark:text-amber-400">
              <ArrowUpCircle class="size-3.5" /> v{{ latest[t.id] }} tersedia
            </div>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <span v-if="info[t.id]?.data" class="mr-auto rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">{{ info[t.id]!.data }}</span>
          <code v-if="t.hint && !info[t.id]?.version" class="mr-auto rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">{{ t.hint }}</code>
          <Button v-for="a in t.actions" :key="a.key" size="sm" :variant="a.label === 'Update program' ? 'outline' : 'secondary'"
            :class="!info[t.id]?.data && a === t.actions[0] && 'ml-auto'" :disabled="busy[a.key]" @click="update(t.id, a.key, `${a.label} ${t.name}`)">
            <Loader2 v-if="busy[a.key]" class="animate-spin" /><Download v-else /> {{ a.label === 'Update program' && info[t.id] && !info[t.id]!.version ? 'Pasang' : a.label }}
          </Button>
        </div>
        <p v-if="result[t.id]" class="flex items-start gap-1.5 text-xs" :class="result[t.id]!.ok ? 'text-green-600 dark:text-green-400' : 'text-destructive'">
          <CheckCircle2 v-if="result[t.id]!.ok" class="mt-px size-3.5 shrink-0" /><AlertCircle v-else class="mt-px size-3.5 shrink-0" />
          <span class="break-words">{{ result[t.id]!.text }}</span>
        </p>

        <!-- Konfigurasi per tool -->
        <div class="space-y-3 border-t pt-4 text-sm">
          <template v-if="t.id === 'semgrep'">
            <div class="space-y-1.5">
              <Label for="sg-extra">Rule pack tambahan</Label>
              <Input id="sg-extra" v-model="extra" placeholder="p/owasp-top-ten, p/secrets" />
              <p class="text-xs text-muted-foreground">Dipisah koma. Rule pack per bahasa sudah dipilih otomatis dari file project.</p>
            </div>
            <div class="space-y-1.5">
              <Label for="sg-exclude">Abaikan path</Label>
              <Input id="sg-exclude" v-model="exclude" placeholder="tests, vendor, *.min.js" />
            </div>
          </template>
          <div v-else-if="t.id === 'gitleaks'" class="flex items-start gap-3">
            <Switch id="gl-history" v-model="opts.gitleaks_history" />
            <Label for="gl-history" class="block font-normal leading-snug">
              <span class="font-medium">Pindai riwayat git</span>
              <span class="block text-muted-foreground">Secret yang sudah dihapus dari kode tetap bocor lewat riwayat commit. Matikan untuk hanya memindai file saat ini (lebih cepat).</span>
            </Label>
          </div>
          <template v-else-if="t.id === 'trivy'">
            <div v-for="o in TRIVY_OPTS" :key="o.k" class="flex items-start gap-3">
              <Switch :id="`tv-${o.k}`" v-model="opts[o.k]" />
              <Label :for="`tv-${o.k}`" class="block font-normal leading-snug">
                <span class="font-medium">{{ o.label }}</span>
                <span class="block text-muted-foreground">{{ o.desc }}</span>
              </Label>
            </div>
          </template>
          <template v-else-if="t.id === 'nuclei'">
            <div class="flex items-start gap-3">
              <Switch id="nuclei" v-model="dast.nuclei" @update:model-value="saveDast" />
              <Label for="nuclei" class="block font-normal leading-snug">
                <span class="font-medium">Aktifkan di scan URL</span>
                <span class="block text-muted-foreground">Mati secara default. Lambat: bisa beberapa menit per host.</span>
              </Label>
            </div>
            <div class="grid grid-cols-[1fr_8rem] gap-3">
              <div class="space-y-1.5">
                <Label for="nc-tags">Tag template</Label>
                <Input id="nc-tags" v-model="opts.nuclei_tags" :disabled="!dast.nuclei" />
              </div>
              <div class="space-y-1.5">
                <Label for="nc-rate">Request/detik</Label>
                <Input id="nc-rate" v-model.number="opts.nuclei_rate" type="number" min="1" max="500" :disabled="!dast.nuclei" />
              </div>
            </div>
            <div class="flex items-start gap-3">
              <Switch id="nc-crawl" v-model="opts.nuclei_crawl" :disabled="!dast.nuclei" />
              <Label for="nc-crawl" class="block font-normal leading-snug">
                <span class="font-medium">Crawl dengan Katana</span>
                <span class="block text-muted-foreground">Cek exposure juga di direktori yang ditemukan crawler (butuh Katana terpasang).</span>
              </Label>
            </div>
          </template>
          <template v-else-if="t.id === 'testssl' || t.id === 'nmap' || t.id === 'zap'">
            <div class="flex items-start gap-3">
              <Switch :id="`d-${t.id}`" v-model="dast[t.id as 'testssl' | 'nmap' | 'zap']" @update:model-value="saveDast" />
              <Label :for="`d-${t.id}`" class="block font-normal leading-snug">
                <span class="font-medium">Ikut di scan URL biasa</span>
                <span class="block text-muted-foreground">Selalu ikut di Full Scan bila terpasang; nyalakan agar juga jalan di scan dari Dashboard/Target.</span>
              </Label>
            </div>
          </template>
          <p v-else-if="t.mode === 'Intrusif'" class="text-muted-foreground">Hanya jalan lewat mode <span class="font-medium text-foreground">Intrusive Scan</span> di halaman Scan, untuk host yang diizinkan di bawah.</p>
        </div>
      </Card>
    </div>

    <h2 class="pt-2 font-semibold">Scan intrusif</h2>
    <Card class="gap-4 px-5">
      <p class="text-sm text-muted-foreground">
        sqlmap, dalfox, ffuf, dan ZAP active scan mengirim payload serangan sungguhan dan bisa mengubah atau merusak data.
        Selain <code class="rounded bg-muted px-1">localhost</code>, <code class="rounded bg-muted px-1">127.0.0.1</code>, <code class="rounded bg-muted px-1">*.localhost</code>, dan <code class="rounded bg-muted px-1">*.test</code>,
        hanya domain di daftar ini yang boleh dipindai. Jangan masukkan domain produksi.
      </p>
      <div class="grid gap-3 text-sm sm:grid-cols-[1fr_8rem]">
        <div class="space-y-1.5">
          <Label for="in-hosts">Domain dev yang diizinkan</Label>
          <Input id="in-hosts" v-model="hosts" placeholder="dev.app.com, *.staging.app.com" />
          <p class="text-xs text-muted-foreground">Dipisah koma. Awali dengan <code>*.</code> untuk semua subdomain.</p>
        </div>
        <div class="space-y-1.5">
          <Label for="in-rate">Request/detik</Label>
          <Input id="in-rate" v-model.number="opts.intrusive_rate" type="number" min="1" max="500" />
        </div>
      </div>
    </Card>

    <h2 class="pt-2 font-semibold">Layanan online</h2>
    <Card class="px-5">
      <div class="flex items-start gap-3 text-sm">
        <Switch id="online" v-model="dast.online" @update:model-value="saveDast" />
        <Label for="online" class="block font-normal leading-snug">
          <span class="font-medium">Mozilla HTTP Observatory</span>
          <span class="block text-muted-foreground">Second opinion untuk header & TLS, selalu versi terbaru karena layanan online. Hostname target dikirim ke Mozilla dan hasilnya bisa tercatat di layanan mereka; hanya untuk host publik, maksimal satu scan per host per menit.</span>
        </Label>
      </div>
    </Card>

    <p class="text-xs text-muted-foreground">Modul bawaan (Headers, TLS, Ports, Files) ikut aplikasi dan diperbarui bersama versi aplikasi. Unduhan tool diverifikasi checksum SHA-256 sebelum dipasang.</p>
  </main>
</template>
