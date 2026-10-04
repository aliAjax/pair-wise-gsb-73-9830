/**
 * 浏览器环境冒烟：localStorage 桩 + Pinia store，验证
 * 建批次→冲突→注入故障→刷新（重新 load store）→自动续做→逐确认→定稿→本地编辑触发接受失效。
 */
import assert from 'node:assert/strict'
import { createPinia, setActivePinia } from 'pinia'

// localStorage 桩
const storage = new Map<string, string>()
;(globalThis as any).localStorage = {
  getItem: (k: string) => (storage.has(k) ? storage.get(k)! : null),
  setItem: (k: string, v: string) => storage.set(k, String(v)),
  removeItem: (k: string) => storage.delete(k),
}
;(globalThis as any).structuredClone = <T,>(v: T): T => JSON.parse(JSON.stringify(v))

const { useThreatModelStore } = await import('@/stores/threatModel' as string)
const { buildSampleExchangePackage } = await import('@/services/exchangePackage' as string)

const freshStore = () => {
  setActivePinia(createPinia())
  return useThreatModelStore()
}

let store = freshStore()
const conflictCountBefore = store.data.threats.length
assert.ok(conflictCountBefore >= 3)

// 1. 导入示例包
const pkg = buildSampleExchangePackage(store.data)
const batch = store.startImport(pkg)
assert.ok(batch, '批次已创建')
assert.equal(store.activeBatch?.status, 'awaiting_confirmation')
const conflicts = store.activeBatch!.items.filter((i) => i.status === 'conflict')
assert.ok(conflicts.length >= 2, `应存在冲突，实际 ${conflicts.length}`)

// 2. 确认一个冲突（包内版）
const first = conflicts[0]
store.resolveImportConflict(first.key, 'incoming')
assert.ok(!store.lastWriteError)
assert.equal(store.activeBatch!.items.find((i) => i.key === first.key)?.status, 'resolution_applied')

// 3. 注入故障后确认下一个冲突
store.armWriteFailure()
const second = store.activeBatch!.items.find((i) => i.status === 'conflict')!
store.resolveImportConflict(second.key, 'incoming')
assert.ok(store.lastWriteError, '写入应失败并被捕获')
assert.equal(store.activeBatch?.status, 'failed')

// 4. 模拟重开页面：重新创建 store，未完成批次应从 localStorage 恢复并可续做
store = freshStore()
assert.ok(store.activeBatch, '刷新后批次仍在（独立批次存储键）')
store.resumeOnLoad() // failed 状态会自动续做
assert.ok(!store.lastWriteError, `续做不应失败：${store.lastWriteError ?? ''}`)
assert.equal(
  store.activeBatch!.items.find((i) => i.key === second.key)?.status,
  'resolution_applied',
  '故障前确认的结论续做后落地',
)

// 5. 剩余冲突逐条确认直到定稿
let guard = 0
while (store.activeBatch && guard++ < 20) {
  const item = store.activeBatch.items.find((i) => i.status === 'conflict')
  if (!item) break
  store.resolveImportConflict(item.key, 'incoming')
  if (store.lastWriteError) throw new Error(store.lastWriteError)
}
assert.ok(!store.activeBatch, '所有冲突确认后批次定稿并退出活动态')
assert.ok(store.data.versions[0].sourceBatchId, '定稿版本绑定批次')
assert.ok(store.data.versions[0].batchConclusion, '版本带批次结论')
assert.equal(store.data.versions[0].batchConclusion!.batchId, store.batches[0].id)

// 6. 重放不重复：再次刷新 + resumeOnLoad，审计与版本不增加
const versionsBefore = store.data.versions.length
const auditsBefore = store.data.audit.filter((a) => a.action === '交换包导入定稿').length
store = freshStore()
store.resumeOnLoad()
assert.equal(store.data.versions.length, versionsBefore)
assert.equal(store.data.audit.filter((a) => a.action === '交换包导入定稿').length, auditsBefore)

// 7. 本地编辑威胁导致其风险接受立即失效
const acceptedRisk = store.data.risks.find((r) => r.status === 'accepted')
if (acceptedRisk) {
  const acceptance = store.data.acceptances.find(
    (a) => a.id === acceptedRisk.activeAcceptanceId && a.status === 'active',
  )
  assert.ok(acceptance, '存在生效接受')
  const linkedThreat = store.data.threats.find((t) => t.riskIds.includes(acceptedRisk.id))!
  const updated = { ...linkedThreat, title: `${linkedThreat.title}（本地二次修订）`, revision: linkedThreat.revision + 1, reviewStatus: 'in_review' as const }
  store.saveThreat(updated)
  const after = store.data.acceptances.find((a) => a.id === acceptance!.id)
  assert.equal(after?.status, 'invalidated', '威胁一变，接受立即失效')
  assert.ok(after?.basisDetail, '失效接受保留依据')
  assert.ok(
    store.issues.some((i) => i.kind === 'risk_acceptance_invalidated' && i.entityId === acceptedRisk.id),
    '校验面板出现接受失效问题',
  )
}

console.log('✅ Store 浏览器流程冒烟通过')
