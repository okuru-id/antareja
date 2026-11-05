<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-dialog'
import { FolderOpen, Globe, Plus, Trash2, AlertCircle, Play, Loader2, Link2 } from '@lucide/vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { type Kind, type Target, dropped, progress, runScan, targets, refresh } from './store'

const blank = (type: Kind = 'Url') => ({ type, value: '', label: '', owned: false })
const form = ref(blank())
const error = ref('')
const load = refresh

async function pickFolder() {
  const dir = await open({ directory: true })
  if (dir) form.value.value = dir
}

watch(dropped, (path) => {
  if (path) form.value = { ...blank('SourcePath'), value: path }
  dropped.value = ''
}, { immediate: true })

async function add() {
  error.value = ''
  try {
    const f = form.value
    await invoke('add_target', { kind: { type: f.type, value: f.value }, label: f.label, owned: f.owned })
    form.value = blank(f.type)
    await load()
  } catch (e) {
    error.value = String(e)
  }
}

const partners = (t: Target) => targets.value.filter((o) => o.kind.type !== t.kind.type)

async function link(t: Target, other: string) {
  error.value = ''
  try {
    await invoke('link_target', { id: t.id, other: other === 'none' ? null : other })
    await load()
  } catch (e) {
    error.value = String(e)
  }
}

async function remove(t: Target) {
  await invoke('remove_target', { id: t.id })
  await load()
}

async function scan(t: Target) {
  error.value = ''
  try {
    await runScan(t)
  } catch (e) {
    error.value = String(e)
  }
}

onMounted(load)
</script>

<template>
  <main class="w-full space-y-6 px-6 pb-6">
    <Card>
      <CardHeader>
        <CardTitle>Tambah target</CardTitle>
        <CardDescription>URL untuk scan DAST, atau folder project untuk scan SAST. Folder juga bisa di-drag ke jendela ini.</CardDescription>
      </CardHeader>
      <CardContent>
        <form class="space-y-4" @submit.prevent="add">
          <div class="flex flex-wrap gap-2">
            <Select v-model="form.type">
              <SelectTrigger class="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="Url">URL (DAST)</SelectItem>
                <SelectItem value="SourcePath">Folder project (SAST)</SelectItem>
              </SelectContent>
            </Select>
            <Input v-model="form.value" required class="min-w-56 flex-[2]"
              :placeholder="form.type === 'Url' ? 'https://app.contoh.co.id' : '/home/user/project'" />
            <Button v-if="form.type === 'SourcePath'" type="button" variant="outline" @click="pickFolder">
              <FolderOpen /> Pilih
            </Button>
            <Input v-model="form.label" placeholder="Label (opsional)" class="min-w-36 flex-1" />
          </div>
          <div class="flex items-start gap-3">
            <Checkbox id="owned" v-model="form.owned" class="mt-0.5" />
            <Label for="owned" class="block font-normal leading-snug text-muted-foreground">
              Saya menyatakan target ini milik tim saya atau sudah ada izin tertulis untuk memindainya.
              Memindai aset milik orang lain tanpa izin bisa melanggar hukum.
            </Label>
          </div>
          <Button type="submit" :disabled="!form.owned"><Plus /> Tambah target</Button>
        </form>
      </CardContent>
    </Card>

    <Alert v-if="error" variant="destructive">
      <AlertCircle />
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <section class="space-y-2">
      <h2 class="text-sm font-medium text-muted-foreground">Target terdaftar ({{ targets.length }})</h2>
      <p v-if="!targets.length" class="text-sm text-muted-foreground">Belum ada target terdaftar.</p>
      <Card v-for="t in targets" :key="t.id" class="flex-row items-center gap-3 px-4 py-3">
        <component :is="t.kind.type === 'Url' ? Globe : FolderOpen" class="size-4 shrink-0 text-muted-foreground" />
        <div class="min-w-0 flex-1">
          <div class="font-medium">{{ t.label }}</div>
          <div class="truncate text-xs text-muted-foreground">{{ progress[t.id] ?? t.kind.value }}</div>
        </div>
        <Select v-if="partners(t).length" :model-value="t.linked ?? 'none'" @update:model-value="(v) => link(t, String(v))">
          <SelectTrigger size="sm" class="w-44" title="Tautkan folder ↔ URL aplikasi yang sama untuk korelasi DAST↔SAST">
            <Link2 class="size-3.5 text-muted-foreground" /><SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">Tidak ditautkan</SelectItem>
            <SelectItem v-for="o in partners(t)" :key="o.id" :value="o.id">{{ o.label }}</SelectItem>
          </SelectContent>
        </Select>
        <Badge variant="secondary">{{ t.kind.type === 'Url' ? 'DAST' : 'SAST' }}</Badge>
        <Button size="sm" :disabled="t.id in progress" @click="scan(t)">
          <Loader2 v-if="t.id in progress" class="animate-spin" /><Play v-else /> Scan
        </Button>
        <AlertDialog>
          <AlertDialogTrigger as-child>
            <Button variant="ghost" size="icon-sm" title="Hapus"><Trash2 /></Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Hapus target "{{ t.label }}"?</AlertDialogTitle>
              <AlertDialogDescription>Target beserta hasil scan-nya dihapus dari daftar.</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Batal</AlertDialogCancel>
              <AlertDialogAction variant="destructive" @click="remove(t)">Hapus</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </Card>
    </section>

  </main>
</template>
