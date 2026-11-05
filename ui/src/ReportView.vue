<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import DOMPurify from 'dompurify'
import { Save, FolderOpen, FileDown, AlertCircle, FileText, Loader2, CheckCircle2, Copy, Check, Boxes } from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Alert, AlertDescription } from '@/components/ui/alert'
import type { Target } from './store'
import { enhanceReport } from './reportEnhance'

const targets = ref<Target[]>([])
const scope = ref('all')
const md = ref('')
const source = ref('') // '' = pratinjau dari database, selain itu path file yang dibuka
const error = ref('')
const targetId = () => (scope.value === 'all' ? null : scope.value)

// Render di Rust (marked macet di WebKitGTK untuk laporan besar).
// File .md bisa dari mana saja: HTML-nya wajib disanitasi sebelum masuk webview.
const html = ref('')
watch(md, async (v) => (html.value = enhanceReport(DOMPurify.sanitize(await invoke<string>('markdown_html', { md: v })))))

async function preview() {
  error.value = ''
  source.value = ''
  md.value = await invoke<string>('report_markdown', { targetId: targetId() })
}

async function saveReport() {
  error.value = ''
  const path = await save({ defaultPath: `laporan-appsec-${new Date().toISOString().slice(0, 10)}.md`, filters: [{ name: 'Markdown', extensions: ['md'] }] })
  if (!path) return
  try {
    source.value = await invoke<string>('save_report', { path, targetId: targetId() })
  } catch (e) {
    error.value = String(e)
  }
}

async function openFile() {
  error.value = ''
  const path = await open({ filters: [{ name: 'Markdown', extensions: ['md', 'markdown'] }] })
  if (!path) return
  try {
    md.value = await invoke<string>('read_markdown', { path })
    source.value = path
  } catch (e) {
    error.value = String(e)
  }
}

// PDF dibuat dari tampilan laporan ini (CSS print), langsung ke file tanpa dialog cetak.
const pdfBusy = ref(false)
const pdfSaved = ref('')
async function generatePdf() {
  error.value = ''
  pdfSaved.value = ''
  const path = await save({ defaultPath: `laporan-appsec-${new Date().toISOString().slice(0, 10)}.pdf`, filters: [{ name: 'PDF', extensions: ['pdf'] }] })
  if (!path) return
  pdfBusy.value = true
  // Kertas selalu terang: matikan tema gelap selama PDF dibuat.
  const root = document.documentElement
  const wasDark = root.classList.contains('dark')
  root.classList.remove('dark')
  try {
    pdfSaved.value = await invoke<string>('print_pdf', { path })
  } catch (e) {
    error.value = String(e)
  } finally {
    root.classList.toggle('dark', wasDark)
    pdfBusy.value = false
  }
}

// Salin Markdown laporan ke clipboard (siap tempel ke issue/chat).
const copied = ref(false)
async function copyReport() {
  error.value = ''
  try {
    await navigator.clipboard.writeText(md.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch (e) {
    error.value = `Gagal menyalin: ${e}`
  }
}

// SBOM CycloneDX (daftar komponen + lisensi) untuk target folder, dibuat Trivy.
const sast = () => targets.value.find((t) => t.id === scope.value && t.kind.type === 'SourcePath')
const sbomBusy = ref(false)
async function exportSbom() {
  const t = sast()
  if (!t) return
  error.value = ''
  pdfSaved.value = ''
  const name = t.label.split('/').filter(Boolean).at(-1) ?? 'project'
  const path = await save({ defaultPath: `sbom-${name}.cdx.json`, filters: [{ name: 'CycloneDX JSON', extensions: ['json'] }] })
  if (!path) return
  sbomBusy.value = true
  try {
    pdfSaved.value = await invoke<string>('export_sbom', { targetId: t.id, path })
  } catch (e) {
    error.value = String(e)
  } finally {
    sbomBusy.value = false
  }
}

// Link di laporan jangan menavigasi webview aplikasi.
const blockLinks = (e: MouseEvent) => (e.target as HTMLElement).closest('a') && e.preventDefault()

onMounted(async () => {
  targets.value = (await invoke<{ target: Target }[]>('latest_scans')).map((d) => d.target)
  await preview()
})
watch(scope, preview)
</script>

<template>
  <main class="w-full space-y-4 px-6 pb-6 print:p-0">
    <div class="flex flex-wrap items-center gap-2 print:hidden">
      <Select v-model="scope">
        <SelectTrigger class="w-56"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Semua target</SelectItem>
          <SelectItem v-for="t in targets" :key="t.id" :value="t.id">{{ t.label }}</SelectItem>
        </SelectContent>
      </Select>
      <Button @click="saveReport"><Save /> Simpan .md</Button>
      <Button variant="outline" @click="openFile"><FolderOpen /> Buka .md</Button>
      <Button variant="outline" :disabled="!md" @click="copyReport"><Check v-if="copied" class="text-green-600" /><Copy v-else /> {{ copied ? 'Tersalin' : 'Copy' }}</Button>
      <Button v-if="sast()" variant="outline" :disabled="sbomBusy" title="SBOM CycloneDX: daftar komponen & lisensi" @click="exportSbom">
        <Loader2 v-if="sbomBusy" class="animate-spin" /><Boxes v-else /> Export SBOM
      </Button>
      <Button variant="outline" :disabled="pdfBusy || !md" @click="generatePdf"><Loader2 v-if="pdfBusy" class="animate-spin" /><FileDown v-else /> Generate PDF</Button>
    </div>

    <p class="flex items-center gap-1.5 text-xs text-muted-foreground print:hidden">
      <FileText class="size-3.5" />
      <template v-if="source">{{ source }}</template>
      <template v-else>Pratinjau dari hasil scan terakhir (belum disimpan)</template>
      <button v-if="source" class="ml-1 underline" @click="preview">kembali ke pratinjau</button>
    </p>

    <Alert v-if="pdfSaved" class="print:hidden">
      <CheckCircle2 />
      <AlertDescription class="break-all">File disimpan: {{ pdfSaved }}</AlertDescription>
    </Alert>

    <Alert v-if="error" variant="destructive" class="print:hidden">
      <AlertCircle />
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- HTML dari Markdown sudah disanitasi DOMPurify (lihat watch md). -->
    <!-- nosemgrep: javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html -->
    <article class="md-body rounded-lg border bg-card p-8 print:border-0 print:p-0" @click="blockLinks" v-html="html" />
  </main>
</template>
