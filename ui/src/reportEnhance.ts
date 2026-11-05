// Percantik HTML laporan (hasil Markdown yang SUDAH disanitasi): kartu ringkasan, kartu per temuan,
// badge severity, dan sorotan baris bukti. Hanya memindah/menambah elemen; teks tetap lewat textContent.
import { SEV_COLOR, type Severity } from './store'

const isSev = (s: string): s is Severity => s in SEV_COLOR
const el = (tag: string, cls: string, text?: string) => {
  const e = document.createElement(tag)
  e.className = cls
  if (text !== undefined) e.textContent = text
  return e
}

export function enhanceReport(clean: string) {
  const t = document.createElement('template')
  t.innerHTML = clean
  const root = t.content

  // Judul + baris "Dibuat: ..." jadi header.
  const h1 = root.querySelector('h1')
  if (h1) {
    const head = el('header', 'rep-head')
    const meta = h1.nextElementSibling
    h1.before(head)
    head.append(h1)
    if (meta?.tagName === 'P') head.append(meta)
  }

  for (const table of root.querySelectorAll('table')) {
    const rows = [...table.querySelectorAll('tbody tr')].map((r) => [...(r as HTMLTableRowElement).cells].map((c) => c.textContent!.trim()))
    // Tabel "Severity | Jumlah" jadi kartu angka.
    if (rows.length && rows.every((r) => r.length === 2 && isSev(r[0]!))) {
      const tiles = el('div', 'rep-tiles')
      for (const [s, n] of rows) {
        const tile = el('div', n === '0' ? 'rep-tile zero' : 'rep-tile')
        tile.style.setProperty('--sev', SEV_COLOR[s as Severity])
        tile.append(el('span', '', s), el('b', '', n))
        tiles.append(tile)
      }
      table.replaceWith(tiles)
      continue
    }
    // Tabel lain: kolom severity diwarnai, angka 0 diredam.
    const heads = [...table.querySelectorAll('th')].map((h) => h.textContent!.trim())
    for (const r of table.querySelectorAll('tbody tr')) {
      ;[...(r as HTMLTableRowElement).cells].forEach((c, i) => {
        const h = heads[i]!
        if (!isSev(h)) return
        if (c.textContent!.trim() === '0') c.className = 'rep-zero'
        else c.style.color = SEV_COLOR[h]
        c.style.fontWeight = '600'
      })
    }
    const wrap = el('div', 'rep-table')
    table.before(wrap)
    wrap.append(table)
  }

  for (const q of root.querySelectorAll('blockquote')) q.className = 'rep-note'
  // Daftar detail (Jenis/Lokasi/Tool/Status) tepat setelah judul jadi baris meta.
  for (const h of root.querySelectorAll('h2, h3')) {
    const ul = h.nextElementSibling
    if (ul?.tagName === 'UL') ul.className = 'rep-meta'
  }
  // Paragraf yang hanya berisi teks tebal = label bagian ("Apa masalahnya", ...).
  for (const p of root.querySelectorAll('p')) {
    if (p.childNodes.length === 1 && p.firstElementChild?.tagName === 'STRONG') p.className = 'rep-label'
  }

  // Tiap "### 1. [Critical] Judul" + isinya dibungkus kartu temuan.
  for (const h3 of root.querySelectorAll('h3')) {
    const m = h3.textContent!.match(/^(\d+)\.\s*\[(\w+)\]\s*(.*)$/)
    if (!m || !isSev(m[2]!)) continue
    const card = el('section', 'rep-finding')
    card.style.setProperty('--sev', SEV_COLOR[m[2]])
    h3.replaceChildren(el('span', 'rep-num', `#${m[1]}`), el('span', 'rep-badge', m[2]), el('span', '', m[3]))
    h3.before(card)
    let n = h3.nextElementSibling
    card.append(h3)
    while (n && !/^H[1-3]$/.test(n.tagName)) {
      const next = n.nextElementSibling
      card.append(n)
      n = next
    }
    // Bukti kode: baris bertanda ">" (baris temuan) disorot.
    for (const code of card.querySelectorAll('pre code')) {
      const lines = code.textContent!.replace(/\n$/, '').split('\n')
      code.replaceChildren(...lines.map((l) => el('span', /^>\s/.test(l) ? 'hl' : '', l || ' ')))
    }
  }

  const div = document.createElement('div')
  div.append(root)
  return div.innerHTML
}
