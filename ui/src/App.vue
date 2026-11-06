<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { getCurrentWebview } from '@tauri-apps/api/webview'
import TitleBar from './TitleBar.vue'
import DashboardView from './DashboardView.vue'
import ScanView from './ScanView.vue'
import TargetsView from './TargetsView.vue'
import FindingsView from './FindingsView.vue'
import ReportView from './ReportView.vue'
import SbomView from './SbomView.vue'
import SettingsView from './SettingsView.vue'
import LogPanel from './LogPanel.vue'
import StatusBar from './StatusBar.vue'
import { LayoutDashboard, Crosshair, Bug, FileText, Boxes, Settings, Play } from '@lucide/vue'
import { tab, dropped, logOpen, sidebarMini, scans, openFindings, refresh } from './store'

const PAGES = {
  dashboard: { label: 'Dashboard', icon: LayoutDashboard, view: DashboardView, sub: 'Ringkasan keamanan aplikasi dan hasil pemindaian.' },
  targets: { label: 'Target', icon: Crosshair, view: TargetsView, sub: 'URL untuk scan DAST dan folder project untuk scan SAST.' },
  scan: { label: 'Scan', icon: Play, view: ScanView, sub: 'Jalankan pemindaian keamanan pada target aplikasi.' },
  findings: { label: 'Temuan', icon: Bug, view: FindingsView, sub: 'Hasil scan terakhir dari setiap target.' },
  report: { label: 'Laporan', icon: FileText, view: ReportView, sub: 'Pratinjau, simpan, dan buka laporan Markdown.' },
  sbom: { label: 'SBOM', icon: Boxes, view: SbomView, sub: 'Daftar komponen & lisensi project (CycloneDX).' },
  settings: { label: 'Pengaturan', icon: Settings, view: SettingsView, sub: 'Versi, update, dan konfigurasi tool scan.' },
} as const
type Page = keyof typeof PAGES
const page = computed(() => PAGES[tab.value as Page] ?? PAGES.dashboard)
const go = (p: string) => (tab.value = p)

const openCount = computed(() => scans.value.reduce((n, d) => n + openFindings(d.scan).length, 0))

onMounted(refresh)

// Drag folder ke jendela -> isi form target SAST.
getCurrentWebview().onDragDropEvent((e) => {
  if (e.payload.type === 'drop' && e.payload.paths[0]) {
    dropped.value = e.payload.paths[0]
    tab.value = 'targets'
  }
})
</script>

<template>
  <div class="flex h-full flex-col bg-background text-foreground print:h-auto">
    <TitleBar class="print:hidden" :title="page.label" :sub="page.sub" />
    <div class="flex min-h-0 flex-1">
      <!-- Mini/lebar: hanya lebar yang dianimasikan; label tetap ter-render (nowrap) lalu memudar, jadi ikon tidak bergeser.
           Tanpa overflow-hidden agar tooltip mini bisa keluar ke kanan; label sudah opacity-0 saat mini. -->
      <aside class="flex shrink-0 flex-col border-r bg-sidebar p-3 transition-[width] duration-200 ease-out print:hidden" :class="sidebarMini ? 'w-16' : 'w-56'">
        <nav class="space-y-1">
          <button v-for="(p, key) in PAGES" :key="key" class="group relative flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm whitespace-nowrap transition-colors"
            :class="tab === key ? 'bg-primary/10 font-medium text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground'"
            @click="go(key)">
            <component :is="p.icon" class="size-4 shrink-0" />
            <span class="transition-opacity duration-200" :class="sidebarMini && 'opacity-0'">{{ p.label }}</span>
            <template v-if="key === 'findings' && openCount">
              <span class="ml-auto rounded-full bg-muted px-2 text-xs tabular-nums text-muted-foreground transition-opacity duration-200" :class="sidebarMini && 'opacity-0'">{{ openCount }}</span>
              <span class="absolute top-1 left-6 size-1.5 rounded-full bg-primary transition-opacity duration-200" :class="!sidebarMini && 'opacity-0'" />
            </template>
            <!-- Tooltip mini -->
            <span v-if="sidebarMini" class="tip">
              {{ p.label }}<span v-if="key === 'findings' && openCount" class="ml-1 font-semibold text-primary">{{ openCount }}</span>
            </span>
          </button>
        </nav>
      </aside>

      <div class="flex min-w-0 flex-1 flex-col">
        <div class="flex min-h-0 flex-1">
          <div class="@container relative min-h-0 min-w-0 flex-1 overflow-auto pt-6 print:overflow-visible print:pt-0">
            <component :is="page.view" />
          </div>
          <LogPanel v-if="logOpen" />
        </div>
      </div>
    </div>
    <StatusBar class="print:hidden" />
  </div>
</template>

<style scoped>
/* Tooltip side menu mini: muncul ke kanan saat hover, dengan caret. */
.tip {
  position: absolute;
  left: 100%;
  top: 50%;
  margin-left: 0.75rem;
  transform: translateY(-50%) translateX(-4px) scale(0.96);
  transform-origin: left center;
  white-space: nowrap;
  border-radius: 0.5rem;
  background: var(--popover);
  color: var(--popover-foreground);
  padding: 0.375rem 0.625rem;
  font-size: 0.75rem;
  font-weight: 500;
  line-height: 1.1;
  box-shadow: 0 6px 20px -4px rgb(0 0 0 / 0.18);
  border: 1px solid var(--border);
  opacity: 0;
  pointer-events: none;
  z-index: 50;
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.tip::before {
  content: '';
  position: absolute;
  left: -4px;
  top: 50%;
  width: 0.5rem;
  height: 0.5rem;
  transform: translateY(-50%) rotate(45deg);
  background: var(--popover);
  border-left: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
.group:hover > .tip {
  opacity: 1;
  transform: translateY(-50%) translateX(0) scale(1);
}
@media (prefers-reduced-motion: reduce) {
  .tip { transition: opacity 0.15s ease; transform: translateY(-50%); }
  .group:hover > .tip { transform: translateY(-50%); }
}
</style>
