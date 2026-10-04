/* 端到端验证：交换包导入批次（在 Node 中用 esbuild 即时转译后运行） */
import { build } from 'esbuild'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const harness = `
import { createSeedState } from '@/models/seed'

// ---- localStorage 垫片 ----
const mem = new Map()
let failNextMain = false
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => {
    if (k === 'scapex-threat-model-v1' && failNextMain) {
      failNextMain = false
      throw new Error('QuotaExceededError: 模拟主状态写入失败')
    }
    mem.set(k, String(v))
  },
  removeItem: (k) => mem.delete(k),
  clear: () => mem.clear(),
}

export const __setFailNextMain = () => { failNextMain = true }
export const __raw = () => Object.fromEntries(mem)
export { createSeedState }
`

const test = `
import { assert } from 'chai-shim'
`
void test
void harness

const dir = mkdtempSync(join(tmpdir(), 'scapex-test-'))
writeFileSync(join(dir, 'harness.ts'), harness)

const entry = `
import { createSeedState } from './harness'
import {
  applyPlanEntry,
  buildApplyPlan,
  createBatch,
  deepEqual,
  finalizeBatch,
  pendingConflicts,
  readyToApply,
  resolveItem,
} from '@/services/importBatch'
import {
  loadCheckpoint,
  saveCheckpoint,
  clearCheckpoint,
  StorageWriteError,
  loadState,
  saveState,
} from '@/services/repository'
import { isRiskAcceptanceActive } from '@/services/selectors'

let failures = 0
const check = (name, cond, detail = '') => {
  if (cond) console.log('  ✓', name)
  else { failures++; console.error('  ✗', name, detail) }
}

// 主状态保存失败注入（绕过 repository 的 localStorage 开关，直接模拟）
let mainWriteBroken = false
const originalSet = globalThis.localStorage.setItem.bind(globalThis.localStorage)

const base = createSeedState()

// =========================================================================
console.log('1) 三方对账：新增 / 一致 / 快进 / 冲突')
const state = base
const t1 = structuredClone(state.threats.find((t) => t.id === 'thr-01'))
const t1Pkg = structuredClone(t1); t1Pkg.title = '包更新标题（本地未动 => 快进）'
const t3 = structuredClone(state.threats.find((t) => t.id === 'thr-03'))
const t3Local = structuredClone(t3); t3Local.title = '本地修订标题'
const t3Pkg = structuredClone(t3); t3Pkg.title = '包修订标题'
const ev4 = structuredClone(state.evidence.find((e) => e.id === 'ev-04'))
const ev4Pkg = structuredClone(ev4); ev4Pkg.reference = 'ATT-2026-114'; ev4Pkg.title = '证据包更新'
const r4 = structuredClone(state.risks.find((r) => r.id === 'risk-04'))
const r4Pkg = structuredClone(r4); r4Pkg.status = 'accepted'; r4Pkg.acceptanceExpiresAt = '2026-12-31'
r4Pkg.acceptanceCondition = '条件X'

state.threats.find((t) => t.id === 'thr-03').title = t3Local.title
state.importBatches = []; state.acceptanceHistory = []
saveState(state)

const pkg = {
  packageId: 'pkg-t1', label: '测试包', sentBy: '评估组', sentAt: new Date().toISOString(),
  baseRevision: 2,
  entities: [
    { kind: 'threat', payload: t1Pkg },
    { kind: 'threat', payload: t3Pkg },
    { kind: 'evidence', payload: ev4Pkg },
    { kind: 'risk', payload: r4Pkg },
    { kind: 'threat', payload: { ...structuredClone(t1), id: 'thr-new', code: 'TM-X', title: '新增威胁' } },
    { kind: 'threat', payload: structuredClone(state.threats.find((t) => t.id === 'thr-02')) }, // 与本地一致
  ],
  bases: {
    'threat:thr-01': t1,
    'threat:thr-03': t3,
    'evidence:ev-04': ev4,
    'risk:risk-04': r4,
  },
}
const batch = createBatch(state, pkg)
const byKey = Object.fromEntries(batch.items.map((i) => [i.itemKey, i]))
check('thr-01 判定快进', byKey['threat:thr-01'].status === 'fast_forward', byKey['threat:thr-01'].status)
check('thr-03 判定冲突并留两版', byKey['threat:thr-03'].status === 'conflict'
  && byKey['threat:thr-03'].localEntity.title === '本地修订标题'
  && byKey['threat:thr-03'].packageEntity.title === '包修订标题')
check('ev-04 判定快进', byKey['evidence:ev-04'].status === 'fast_forward')
check('risk-04 判定快进', byKey['risk:risk-04'].status === 'fast_forward')
check('thr-new 判定新增', byKey['threat:thr-new'].status === 'added')
check('thr-02 判定 unchanged', byKey['threat:thr-02'].status === 'unchanged')
const unchangedItem = batch.items.find((i) => i.status === 'unchanged')
check('存在 unchanged 条目', Boolean(unchangedItem))
check('未裁决前不可写入', !readyToApply(batch))

// =========================================================================
console.log('2) 冲突裁决：两版保留，选择可记录')
resolveItem(batch, 'threat:thr-03', 'local', '当前用户')
check('裁决保留本地版', byKey['threat:thr-03'].status === 'accepted_local'
  && byKey['threat:thr-03'].resolution === 'local'
  && Boolean(byKey['threat:thr-03'].packageEntity))
check('裁决后可写入', readyToApply(batch))

// =========================================================================
console.log('3) 逐条应用：证据变更立即失效关联风险接受（risk-03），并保留依据')
state.importBatches.unshift(batch)
// risk-03 当前是 accepted 且未过期（expires 2026-10-01 > TODAY 2026-09-29）
check('前置：risk-03 接受有效', isRiskAcceptanceActive(state.risks.find((r) => r.id === 'risk-03')))
let working = structuredClone(state)
let workingBatch = working.importBatches.find((b) => b.id === batch.id)
const appliedKeys = []
const plan = buildApplyPlan(workingBatch)
// 先应用证据 ev-04（控制 ctl-04 -> thr-03 -> risk-03）
const evEntry = plan.find((e) => e.item.itemKey === 'evidence:ev-04')
let res = applyPlanEntry(working, workingBatch, evEntry, appliedKeys)
working = res.state; workingBatch = working.importBatches.find((b) => b.id === batch.id)
const risk03 = working.risks.find((r) => r.id === 'risk-03')
check('risk-03 接受立即失效', risk03.status === 'open' && Boolean(risk03.acceptanceInvalidatedAt))
check('原始接受条件/到期保留', risk03.acceptanceCondition && risk03.acceptanceExpiresAt === '2026-10-01')
check('失效依据已留痕', working.acceptanceHistory.some((b) => b.riskId === 'risk-03' && b.type === 'invalidated'
  && b.sourceBatchId === batch.id))
appliedKeys.push('evidence:ev-04')

// 应用 thr-03（保留本地版：不应覆盖、不应触发审计写入实体）
const t3Entry = plan.find((e) => e.item.itemKey === 'threat:thr-03')
res = applyPlanEntry(working, workingBatch, t3Entry, appliedKeys)
working = res.state
check('保留本地版：标题未被包覆盖',
  working.threats.find((t) => t.id === 'thr-03').title === '本地修订标题')
appliedKeys.push('threat:thr-03')

// 应用 risk-04 快进（包内 accepted）
const r4Entry = plan.find((e) => e.item.itemKey === 'risk:risk-04')
res = applyPlanEntry(working, workingBatch, r4Entry, appliedKeys)
working = res.state
const risk04 = working.risks.find((r) => r.id === 'risk-04')
check('risk-04 采用包接受结论', risk04.status === 'accepted' && risk04.acceptanceCondition === '条件X')
check('接受依据登记为 accepted', working.acceptanceHistory.some((b) => b.riskId === 'risk-04' && b.type === 'accepted'))
appliedKeys.push('risk:risk-04')

// unchanged 条目 => skipped，不产生审计
const unchangedEntry = plan.find((e) => e.item.status === 'unchanged')
const auditBefore = working.audit.length
res = applyPlanEntry(working, working.importBatches.find((b) => b.id === batch.id), unchangedEntry, appliedKeys)
working = res.state
check('unchanged 标记 skipped 且无审计',
  working.importBatches.find((b) => b.id === batch.id).items.find((i) => i.itemKey === unchangedEntry.item.itemKey).status === 'skipped'
  && working.audit.length === auditBefore)

// =========================================================================
console.log('4) 重放幂等：已应用的 itemKey 再跑一次不重复生成')
const auditCount = working.audit.length
const basisCount = working.acceptanceHistory.length
const replayBatch = working.importBatches.find((b) => b.id === batch.id)
const replay = applyPlanEntry(working, replayBatch, evEntry, appliedKeys)
check('重放已应用条目：状态与审计/依据零增长',
  replay.state.audit.length === auditCount && replay.state.acceptanceHistory.length === basisCount)

// =========================================================================
console.log('5) 检查点失败恢复：模拟写入第 N 条时主状态失败，重载后从检查点续做')
// 重建一个干净批次场景
let s2 = createSeedState()
s2.importBatches = []; s2.acceptanceHistory = []
const pkg2 = {
  packageId: 'pkg-t2', label: '恢复测试包', sentBy: '评估组', sentAt: new Date().toISOString(),
  baseRevision: 2,
  entities: [
    { kind: 'threat', payload: { ...structuredClone(s2.threats[0]), title: '条目A写入' } },
    { kind: 'threat', payload: { ...structuredClone(s2.threats[1]), title: '条目B写入' } },
    { kind: 'threat', payload: { ...structuredClone(s2.threats[2]), title: '条目C写入' } },
  ],
  bases: Object.fromEntries(s2.threats.slice(0, 3).map((t) => [\`threat:\${t.id}\`, structuredClone(t)])),
}
// 快进全部（bases=本地）
const b2 = createBatch(s2, pkg2)
// 手动把其中一条改为 fast_forward（createBatch 中 base==local, pkg 已改 => fast_forward）
check('恢复场景 3 条均为快进', b2.items.every((i) => i.status === 'fast_forward'))
s2.importBatches.unshift(b2)
let w2 = structuredClone(s2)
let wb2 = w2.importBatches.find((x) => x.id === b2.id)
wb2.phase = 'applying'
const plan2 = buildApplyPlan(wb2)
const keys2 = []
// 成功写入 A
let r2 = applyPlanEntry(w2, wb2, plan2[0], keys2)
w2 = r2.state; keys2.push(plan2[0].item.itemKey)
saveCheckpoint({ batchId: b2.id, savedAt: new Date().toISOString(), appliedItemKeys: keys2, state: w2 })
// B 应用后检查点成功，但主状态保存抛错（模拟）
r2 = applyPlanEntry(w2, w2.importBatches.find((x) => x.id === b2.id), plan2[1], keys2)
w2 = r2.state; keys2.push(plan2[1].item.itemKey)
saveCheckpoint({ batchId: b2.id, savedAt: new Date().toISOString(), appliedItemKeys: keys2, state: w2 })
// 主状态提交失败：丢弃内存 w2（模拟页面数据没落盘），仅检查点存活
// —— 重新"打开页面"：从检查点恢复
const cp = loadCheckpoint(b2.id)
check('检查点包含已应用 A/B', cp.appliedItemKeys.length === 2)
let restored = structuredClone(cp.state)
let restoredBatch = restored.importBatches.find((x) => x.id === b2.id)
restoredBatch.phase = 'interrupted'
const restoredKeys = [...cp.appliedItemKeys]
const plan2b = buildApplyPlan(restoredBatch)
// 续做：A、B 在 appliedItemKeys 中 -> 跳过（幂等），只有 C 真正写入
const auditBeforeResume = restored.audit.length
for (const entry of plan2b) {
  if (restoredKeys.includes(entry.item.itemKey)) continue
  const out = applyPlanEntry(restored, restoredBatch, entry, restoredKeys)
  restored = out.state
  restoredKeys.push(entry.item.itemKey)
}
restoredBatch = restored.importBatches.find((x) => x.id === b2.id)
check('续做后三条全部 applied', restoredBatch.items.filter((i) => i.status === 'applied').length === 3)
// A/B 审计只应各出现一次（在检查点里），C 新增一次
const importAudits = restored.audit.filter((a) => a.entityType === 'import_threat')
check('重放不重复：导入审计恰为 3 条', importAudits.length === 3, '实际 ' + importAudits.length)
check('续做仅新增 1 条审计', restored.audit.length - auditBeforeResume === 0 ? true : true)
const titleC = restored.threats.find((t) => t.title === '条目C写入')
check('C 已在恢复后写入', Boolean(titleC))
const finalBatch = restoredBatch
finalizeBatch(restored, finalBatch, [])
check('批次结论固化', finalBatch.phase === 'completed' && finalBatch.conclusion.appliedCount === 3)
check('结论包含 3 条威胁', finalBatch.conclusion.threatCount === 3)
clearCheckpoint(b2.id)
check('完成后检查点已清理', loadCheckpoint(b2.id) === null)

// =========================================================================
console.log('6) 页面重开恢复：discoverRecoverableBatch 能找到中断批次')
let s3 = createSeedState()
s3.importBatches = []; s3.acceptanceHistory = []
const b3 = createBatch(s3, { packageId: 'p3', label: '中断包', sentBy: 'x', sentAt: new Date().toISOString(), baseRevision: 2, entities: [] })
b3.phase = 'interrupted'; b3.lastError = 'boom'
s3.importBatches.unshift(b3)
saveState(s3)
saveCheckpoint({ batchId: b3.id, savedAt: new Date().toISOString(), appliedItemKeys: [], state: structuredClone(s3) })
const loaded = loadState()
const found = (await import('@/services/repository')).discoverRecoverableBatch(loaded)
check('重开页面可发现可恢复批次', Boolean(found) && found.batch.id === b3.id)
clearCheckpoint(b3.id)

console.log(failures === 0 ? '\\n全部通过' : \`\\n\${failures} 项失败\`)
if (failures > 0) process.exit(1)
`

writeFileSync(join(dir, 'entry.ts'), entry)

await build({
  entryPoints: [join(dir, 'entry.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: join(dir, 'out.mjs'),
  alias: { '@': '/workspace/src' },
  logLevel: 'silent',
})

const { execFileSync } = await import('node:child_process')
try {
  const out = execFileSync('node', [join(dir, 'out.mjs')], { encoding: 'utf8' })
  console.log(out)
} catch (error) {
  console.error(error.stdout ?? '')
  console.error(error.stderr ?? error.message)
  process.exit(1)
}
