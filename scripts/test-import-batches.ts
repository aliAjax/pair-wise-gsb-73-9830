/**
 * 导入批次引擎端到端测试（node --experimental-strip-types）
 * 覆盖：对账冲突两版、幂等重放不重复、写入失败从检查点恢复、风险接受依据失效重算。
 */
import assert from 'node:assert/strict'
import { createSeedState } from '../src/models/seed.ts'
import { advanceBatch, createBatch, resolveConflict, resumeBatch } from '../src/services/importBatches.ts'
import type { ExchangePackage, ImportBatch, ThreatModelState } from '../src/models/domain.ts'

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v))

const pkg = (): ExchangePackage => ({
  packageId: 'PKG-T-1',
  packageName: '测试交换包',
  sentBy: '外部评估组',
  sentAt: '2026-10-03T00:00:00+08:00',
  threats: [
    {
      externalId: 'thr-01',
      code: 'TM-001',
      title: '管理网关暴露导致凭证与会话双重滥用（修订）',
      category: 'spoofing',
      description: '外部复评更新后的描述。',
      severity: 'critical',
      status: 'mitigating',
      componentIds: ['cmp-01', 'cmp-02'],
      flowIds: ['flow-01'],
      externalDependencyIds: [],
      attackPathIds: ['path-01'],
      controlIds: ['ctl-01'],
      riskIds: ['risk-01'],
      revision: 3,
    },
  ],
  evidence: [
    {
      externalId: 'ev-03',
      controlId: 'ctl-03',
      title: '越权访问扫描报告（外部复评）',
      kind: 'scan',
      reference: 'EXT-SCAN-9012',
      collectedAt: '2026-10-02',
      expiresAt: '2027-01-02',
      owner: '外部评估组',
      valid: true,
    },
  ],
  controls: [],
  riskAcceptances: [
    {
      riskId: 'risk-03',
      expiresAt: '2026-12-31',
      condition: '新条件：接入异常来源地告警后接受。',
      actor: '外部评估组',
      createdAt: '2026-10-03T09:00:00+08:00',
    },
  ],
})

/** 内存存储桩：保存最近一次成功提交的 state/batch，可注入前 N 次失败 */
const makeStore = (failFirst = 0) => {
  const holder: { state: ThreatModelState | null; batch: ImportBatch | null } = {
    state: null,
    batch: null,
  }
  let attempts = 0
  const commit = (state: ThreatModelState, batch: ImportBatch): void => {
    attempts += 1
    if (attempts <= failFirst) throw new Error('storage unavailable')
    holder.state = clone(state)
    holder.batch = clone(batch)
  }
  return {
    holder,
    commit,
    get attempts() {
      return attempts
    },
  }
}

// --- 1. 对账：冲突保留两版，检查点完整 ---
let state = createSeedState()
const initialAcceptanceId = state.acceptances[0]?.id
let batch = createBatch(state, pkg())
assert.equal(batch.items.length, 3)
assert.equal(batch.items.filter((i) => i.conflict).length, 3, '三条均为冲突')
for (const key of ['threat:thr-01', 'evidence:ev-03', 'acceptance:risk-03']) {
  const item = batch.items.find((i) => i.key === key)!
  assert.ok(item.localVersion && item.incomingVersion, `${key} 保留两版`)
}
assert.ok(batch.checkpoint, '建批次即有完整检查点')

// --- 2. 首跑全部冲突 -> awaiting_confirmation，本地数据不被覆盖 ---
let store = makeStore()
let outcome = advanceBatch(state, batch, store.commit)
assert.equal(outcome.awaitingConfirmation, true)
assert.equal(batch.status, 'awaiting_confirmation')
assert.equal(
  store.holder.state!.threats.find((t) => t.id === 'thr-01')?.title,
  '管理网关暴露导致凭证滥用',
)

// --- 3. 确认威胁采用包内版；仍剩两个冲突（沿用同一存储，即同一本地仓库） ---
outcome = resolveConflict(store.holder.state!, batch, 'threat:thr-01', 'incoming', '测试人', store.commit)
assert.equal(outcome.awaitingConfirmation, true)
assert.equal(batch.status, 'awaiting_confirmation')
assert.equal(
  batch.items.find((i) => i.key === 'threat:thr-01')?.status,
  'resolution_applied',
)

// --- 4. 确认证据时写入持续失败 -> failed（用户的版本选择已记录在批次中） ---
const failing = makeStore(99)
assert.throws(() =>
  resolveConflict(store.holder.state!, batch, 'evidence:ev-03', 'incoming', '测试人', failing.commit),
)
assert.equal(batch.status, 'failed')
const failedItem = batch.items.find((i) => i.key === 'evidence:ev-03')!
assert.equal(failedItem.resolution, 'incoming', '失败也保留用户选择的版本结论')

// --- 5. 从检查点续做：已确认威胁与证据按结论幂等重放，接受条目回到待确认 ---
const resumeStore = makeStore()
outcome = resumeBatch(batch, resumeStore.commit)
assert.equal(outcome.awaitingConfirmation, true)
assert.equal(batch.status, 'awaiting_confirmation')
assert.equal(
  batch.items.find((i) => i.key === 'threat:thr-01')?.status,
  'resolution_applied',
  '威胁结论从检查点重放',
)
assert.equal(
  batch.items.find((i) => i.key === 'evidence:ev-03')?.status,
  'resolution_applied',
  '证据按已确认的包内版选择重放',
)
assert.equal(
  batch.items.find((i) => i.key === 'acceptance:risk-03')?.status,
  'conflict',
  '未确认的风险接受保持两版待确认',
)
const appliedThreatCount = batch.items.filter(
  (i) => i.key === 'threat:thr-01' && i.status === 'resolution_applied',
).length
assert.equal(appliedThreatCount, 1)

// --- 6. 再续一次，不重复生成任何记录 ---
resumeBatch(batch, resumeStore.commit)
assert.equal(batch.items.filter((i) => i.status === 'resolution_applied').length, 2)

// --- 7. 风险接受仍需人工确认：保留本地版 ---
outcome = resolveConflict(resumeStore.holder.state!, batch, 'acceptance:risk-03', 'local', '测试人', resumeStore.commit)
assert.equal(outcome.awaitingConfirmation, false)
assert.equal(batch.status, 'completed')

const finalState = resumeStore.holder.state!
assert.equal(finalState.currentRevision, 3, '定稿抬升到 r3')
assert.equal(finalState.versions[0].sourceBatchId, batch.id)
assert.ok(finalState.versions[0].batchConclusion)
assert.deepEqual(
  finalState.versions[0].affectedThreatIds.sort(),
  ['thr-01', 'thr-02', 'thr-03'],
  'thr-01 直接修订；thr-02/thr-03 因证据 ctl-03 变化进入重新会签',
)

// 保留本地接受：包内接受未写入；证据变化后旧接受经重算失效，风险回到开放并保留依据
const risk03 = finalState.risks.find((r) => r.id === 'risk-03')!
assert.equal(risk03.status, 'open', '证据变化导致接受失效，保留本地版即不接受新条款')
assert.equal(risk03.activeAcceptanceId, undefined)
const risk03Records = finalState.acceptances.filter((r) => r.riskId === 'risk-03')
assert.equal(risk03Records.length, 1, '未引入包内接受，仅保留本地历史接受')
assert.equal(risk03Records[0].status, 'invalidated', '旧接受失效但依据保留')
assert.ok(risk03Records[0].basisDetail, '旧接受依据明细保留')
assert.equal(risk03Records[0].id, initialAcceptanceId)
assert.ok(batch.invalidatedAcceptanceIds.includes(initialAcceptanceId!))

// 威胁/证据已落地
assert.equal(
  finalState.threats.find((t) => t.id === 'thr-01')?.title,
  '管理网关暴露导致凭证与会话双重滥用（修订）',
)
assert.equal(
  finalState.evidence.find((e) => e.id === 'ev-03')?.reference,
  'EXT-SCAN-9012',
)

// 审计事件确定性、只生成一次
assert.equal(
  finalState.audit.filter((a) => a.action === '交换包导入定稿').length,
  1,
)

// --- 9. 定稿后再次 resume 为空操作，不重复 ---
store = makeStore()
outcome = resumeBatch(batch, store.commit)
assert.equal(outcome.awaitingConfirmation, false)
assert.equal(batch.status, 'completed')

// --- 10. 另起一批：风险接受采用包内版 -> 旧接受失效留据，新接受生效 ---
const state2 = createSeedState()
const batch2 = createBatch(state2, pkg())
const store2 = makeStore()
advanceBatch(state2, batch2, store2.commit)
resolveConflict(state2, batch2, 'threat:thr-01', 'incoming', '测试人', store2.commit)
resolveConflict(store2.holder.state!, batch2, 'evidence:ev-03', 'incoming', '测试人', store2.commit)
resolveConflict(store2.holder.state!, batch2, 'acceptance:risk-03', 'incoming', '测试人', store2.commit)
assert.equal(batch2.status, 'completed')
const s2 = store2.holder.state!
const r03 = s2.risks.find((r) => r.id === 'risk-03')!
assert.equal(r03.status, 'accepted')
assert.equal(r03.acceptanceCondition, '新条件：接入异常来源地告警后接受。')
const recs = s2.acceptances.filter((r) => r.riskId === 'risk-03')
assert.equal(recs.length, 2, '新旧两版接受都保留')
assert.equal(recs[0].status, 'active')
assert.equal(recs[0].source, 'import')
assert.equal(recs[0].priorRecordId, initialAcceptanceId)
assert.equal(recs[1].status, 'invalidated')

console.log('✅ 全部批次引擎测试通过')
