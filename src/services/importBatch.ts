import type {
  AcceptanceBasis,
  BatchConclusion,
  ControlEvidence,
  ExchangeEntity,
  ExchangeEntityKind,
  ExchangePackage,
  ImportBatch,
  ImportItem,
  ReconcileStatus,
  Risk,
  Threat,
  ThreatModelState,
} from '@/models/domain'
import { createId } from '@/services/repository'

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------

export const deepEqual = (a: unknown, b: unknown): boolean => {
  if (a === b) return true
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false
    return a.every((entry, index) => deepEqual(entry, b[index]))
  }
  const keysA = Object.keys(a as Record<string, unknown>).sort()
  const keysB = Object.keys(b as Record<string, unknown>).sort()
  if (keysA.length !== keysB.length || keysA.some((key, index) => key !== keysB[index])) return false
  return keysA.every((key) =>
    deepEqual(
      (a as Record<string, unknown>)[key],
      (b as Record<string, unknown>)[key],
    ),
  )
}

type CollectionMap = {
  threat: Threat[]
  evidence: ControlEvidence[]
  risk: Risk[]
}

const collectionFor = <K extends ExchangeEntityKind>(
  state: ThreatModelState,
  kind: K,
): CollectionMap[K] => {
  if (kind === 'threat') return state.threats as CollectionMap[K]
  if (kind === 'evidence') return state.evidence as CollectionMap[K]
  return state.risks as CollectionMap[K]
}

export const entityTitle = (entity: Threat | ControlEvidence | Risk): string => {
  if ('code' in entity) return `${entity.code} ${entity.title}`
  return `${entity.title}（${entity.reference}）`
}

const itemKeyFor = (kind: ExchangeEntityKind, id: string): string => `${kind}:${id}`

const kindLabel = (kind: ExchangeEntityKind): string =>
  kind === 'threat' ? '威胁' : kind === 'evidence' ? '控制证据' : '风险接受'

// ---------------------------------------------------------------------------
// 建批次：记住本地修订，与包内内容逐条对账
// ---------------------------------------------------------------------------

const reconcileOne = (
  state: ThreatModelState,
  pkg: ExchangePackage,
  entry: ExchangeEntity,
): ImportItem => {
  const { kind, payload: packageEntity } = entry
  const collection = collectionFor(state, kind)
  const local = collection.find((item) => item.id === packageEntity.id) ?? null
  const key = itemKeyFor(kind, packageEntity.id)
  const base = pkg.bases?.[key] ?? null

  let status: ReconcileStatus
  if (!local) {
    status = 'added'
  } else if (deepEqual(local, packageEntity)) {
    status = 'unchanged'
  } else if (base && deepEqual(local, base)) {
    // 本地仍停留在包导出基线，只有评估组一侧改动 => 快进采用
    status = 'fast_forward'
  } else {
    // 本地相对基线已有修订，包也改了同一实体 => 分叉冲突，两版留档
    status = 'conflict'
  }

  return {
    itemKey: key,
    kind,
    entityId: packageEntity.id,
    status,
    title: entityTitle(packageEntity),
    packageEntity: structuredClone(packageEntity),
    baseEntity: base ? structuredClone(base) : local ? structuredClone(local) : null,
    localEntity: local ? structuredClone(local) : null,
  }
}

export const createBatch = (state: ThreatModelState, pkg: ExchangePackage): ImportBatch => {
  const items = pkg.entities.map((entry) => reconcileOne(state, pkg, entry))
  // 稳定排序：冲突优先，其次威胁/证据/风险，便于逐项确认
  const rank: Record<ReconcileStatus, number> = {
    conflict: 0,
    added: 1,
    fast_forward: 2,
    unchanged: 3,
  }
  items.sort((a, b) => {
    const diff = rank[a.status as ReconcileStatus] - rank[b.status as ReconcileStatus]
    return diff !== 0 ? diff : a.itemKey.localeCompare(b.itemKey)
  })

  return {
    id: createId('batch'),
    packageId: pkg.packageId,
    label: pkg.label,
    sentBy: pkg.sentBy,
    createdAt: new Date().toISOString(),
    phase: 'reconciling',
    baseRevision: pkg.baseRevision,
    items,
    checkpoint: 0,
    lastError: null,
    completedAt: null,
    conclusion: null,
  }
}

// ---------------------------------------------------------------------------
// 冲突裁决：保留两版，人工选择其中一版，选择可更改但全程留痕
// ---------------------------------------------------------------------------

export const resolveItem = (
  batch: ImportBatch,
  itemKey: string,
  resolution: 'local' | 'package',
  actor: string,
): void => {
  const item = batch.items.find((entry) => entry.itemKey === itemKey)
  if (!item || item.status !== 'conflict') return
  item.resolution = resolution
  item.resolvedAt = new Date().toISOString()
  item.resolvedBy = actor
  item.status = resolution === 'local' ? 'accepted_local' : 'accepted_package'
}

export const pendingConflicts = (batch: ImportBatch): ImportItem[] =>
  batch.items.filter((item) => item.status === 'conflict')

/** 批次是否可以进入写入阶段：无未裁决冲突 */
export const readyToApply = (batch: ImportBatch): boolean => pendingConflicts(batch).length === 0

// ---------------------------------------------------------------------------
// 风险接受失效联动
// ---------------------------------------------------------------------------

/** 证据关联到哪些控制，进而影响哪些风险（威胁.controlIds -> 风险） */
const risksAffectedByEvidence = (state: ThreatModelState, evidenceId: string): Risk[] => {
  const controlIds = new Set(
    state.controls
      .filter((control) => control.evidenceIds.includes(evidenceId))
      .map((control) => control.id),
  )
  const riskIds = new Set<string>()
  state.threats.forEach((threat) => {
    if (!threat.controlIds.some((id) => controlIds.has(id))) return
    threat.riskIds.forEach((id) => riskIds.add(id))
  })
  return state.risks.filter((risk) => riskIds.has(risk.id))
}

/** 威胁直接关联的风险 */
const risksAffectedByThreat = (state: ThreatModelState, threatId: string): Risk[] => {
  const threat = state.threats.find((item) => item.id === threatId)
  if (!threat) return []
  return state.risks.filter((risk) => threat.riskIds.includes(risk.id))
}

export interface InvalidationResult {
  invalidated: Risk[]
}

const ACTIVE_ACCEPTED = (risk: Risk): boolean =>
  risk.status === 'accepted' && !risk.acceptanceInvalidatedAt

/**
 * 威胁或证据发生变更后立即重算：关联风险上仍然有效的接受立即失效。
 * 失效不清空原始接受条件与到期日（保留依据），只要求重新确认。
 */
const invalidateAcceptancesForChange = (
  state: ThreatModelState,
  change: { kind: ExchangeEntityKind; entityId: string; batchId?: string; itemKey?: string },
  nowIso: string,
): Risk[] => {
  const risks =
    change.kind === 'threat'
      ? risksAffectedByThreat(state, change.entityId)
      : change.kind === 'evidence'
        ? risksAffectedByEvidence(state, change.entityId)
        : []

  const invalidated: Risk[] = []
  risks.filter(ACTIVE_ACCEPTED).forEach((risk) => {
    const reason =
      change.kind === 'threat'
        ? `关联威胁 ${change.entityId} 已被交换包批次更新，风险接受前提变化`
        : `支撑控制的证据 ${change.entityId} 已被交换包批次更新，风险接受依据变化`
    // 回到开放状态要求重新评审；接受条件与到期日保留在字段与接受依据中
    risk.status = 'open'
    risk.acceptanceInvalidatedAt = nowIso
    risk.acceptanceInvalidatedReason = reason

    const basis: AcceptanceBasis = {
      id: createId('bas'),
      riskId: risk.id,
      riskCode: risk.code,
      type: 'invalidated',
      condition: risk.acceptanceCondition ?? '',
      expiresAt: risk.acceptanceExpiresAt,
      reason,
      sourceBatchId: change.batchId,
      sourceItemKey: change.itemKey,
      createdAt: nowIso,
      createdBy: '系统（导入批次联动）',
    }
    state.acceptanceHistory.unshift(basis)
    invalidated.push(risk)
  })
  return invalidated
}

// ---------------------------------------------------------------------------
// 写入阶段：逐条幂等应用；从检查点续做时重放不重复生成
// ---------------------------------------------------------------------------

export interface ApplyPlanEntry {
  item: ImportItem
  /** 本条是否需要真正写入（added/fast_forward/采用包版本） */
  writable: boolean
  chosen: 'local' | 'package' | 'none'
}

/** 计算待写入序列；unchanged 与保留本地版的条目不产生写操作 */
export const buildApplyPlan = (batch: ImportBatch): ApplyPlanEntry[] =>
  batch.items.map((item) => {
    if (item.status === 'unchanged') {
      return { item, writable: false, chosen: 'none' }
    }
    if (item.status === 'accepted_local' || item.status === 'skipped') {
      return { item, writable: false, chosen: 'local' }
    }
    // added / fast_forward / accepted_package / applied
    return { item, writable: item.status !== 'applied', chosen: 'package' }
  })

const upsertEntity = (
  state: ThreatModelState,
  kind: ExchangeEntityKind,
  entity: Threat | ControlEvidence | Risk,
): void => {
  const collection = collectionFor(state, kind) as (Threat | ControlEvidence | Risk)[]
  const index = collection.findIndex((entry) => entry.id === entity.id)
  if (index >= 0) collection[index] = structuredClone(entity)
  else collection.unshift(structuredClone(entity))
}

const auditForItem = (state: ThreatModelState, entry: ApplyPlanEntry): void => {
  const actionMap: Record<ExchangeEntityKind, string> = {
    threat: '威胁导入',
    evidence: '证据导入',
    risk: '风险接受导入',
  }
  const { item } = entry
  const disposition = entry.chosen === 'local' ? '冲突裁决保留本地版' : '采用交换包版本'
  state.audit.unshift({
    id: createId('aud'),
    entityType: `import_${item.kind}`,
    entityId: item.entityId,
    action: actionMap[item.kind],
    actor: '导入批次',
    createdAt: new Date().toISOString(),
    detail: `批次写入：${item.title}，${disposition}`,
  })
}

export interface ApplyStepResult {
  state: ThreatModelState
  batch: ImportBatch
  invalidatedRiskIds: string[]
}

/**
 * 应用一个计划条目（幂等：itemKey 已在 appliedItemKeys 中则整体跳过）。
 * 返回新的 state（基于传入 state 的拷贝），由调用方负责落盘为检查点。
 */
export const applyPlanEntry = (
  state: ThreatModelState,
  batch: ImportBatch,
  entry: ApplyPlanEntry,
  appliedItemKeys: string[],
): ApplyStepResult => {
  if (appliedItemKeys.includes(entry.item.itemKey)) {
    return { state, batch, invalidatedRiskIds: [] }
  }
  const next: ThreatModelState = structuredClone(state)
  const nextBatch = next.importBatches.find((item) => item.id === batch.id)
  if (!nextBatch) return { state, batch, invalidatedRiskIds: [] }
  const targetItem = nextBatch.items.find((item) => item.itemKey === entry.item.itemKey)
  if (!targetItem) return { state, batch, invalidatedRiskIds: [] }

  const nowIso = new Date().toISOString()
  let invalidated: Risk[] = []

  if (entry.writable && entry.chosen === 'package') {
    upsertEntity(next, entry.item.kind, entry.item.packageEntity)
    invalidated = invalidateAcceptancesForChange(next, {
      kind: entry.item.kind,
      entityId: entry.item.entityId,
      batchId: nextBatch.id,
      itemKey: entry.item.itemKey,
    }, nowIso)
  }

  // 风险条目自带接受：若包内风险处于 accepted，登记/续记接受依据（保留依据）
  if (entry.item.kind === 'risk' && entry.writable) {
    const risk = entry.item.packageEntity as Risk
    if (risk.status === 'accepted' && risk.acceptanceCondition) {
      const previous = next.acceptanceHistory.find(
        (basis) => basis.riskId === risk.id && basis.type !== 'invalidated',
      )
      next.acceptanceHistory.unshift({
        id: createId('bas'),
        riskId: risk.id,
        riskCode: risk.code,
        type: previous ? 'reconfirmed' : 'accepted',
        condition: risk.acceptanceCondition,
        expiresAt: risk.acceptanceExpiresAt,
        reason: `交换包批次 ${nextBatch.label} 带回的风险接受结论`,
        sourceBatchId: nextBatch.id,
        sourceItemKey: entry.item.itemKey,
        createdAt: nowIso,
        createdBy: nextBatch.sentBy,
      })
    }
  }

  if (entry.chosen === 'none') {
    // 对账一致：不写入、不生成审计，仅标记跳过
    targetItem.status = 'skipped'
    return { state: next, batch: nextBatch, invalidatedRiskIds: [] }
  }

  targetItem.status = entry.chosen === 'local' ? 'accepted_local' : 'applied'
  targetItem.appliedAt = nowIso
  auditForItem(next, entry)

  return {
    state: next,
    batch: nextBatch,
    invalidatedRiskIds: invalidated.map((risk) => risk.id),
  }
}

/** 批次完成：固化同一批次结论，版本差异与会签中心都读这份 */
export const finalizeBatch = (
  state: ThreatModelState,
  batch: ImportBatch,
  invalidatedRiskIds: string[],
): BatchConclusion => {
  const appliedThreatIds = [
    ...new Set(
      batch.items
        .filter((item) => item.kind === 'threat' && item.status === 'applied')
        .map((item) => item.entityId),
    ),
  ]
  // 失效风险以接受依据留痕为准，保证中断恢复后结论仍可完整重建
  const historyInvalidated = new Set(
    state.acceptanceHistory
      .filter((basis) => basis.sourceBatchId === batch.id && basis.type === 'invalidated')
      .map((basis) => basis.riskId),
  )
  invalidatedRiskIds.forEach((id) => historyInvalidated.add(id))

  const conclusion: BatchConclusion = {
    threatIds: appliedThreatIds,
    threatCount: batch.items.filter((item) => item.kind === 'threat').length,
    evidenceCount: batch.items.filter((item) => item.kind === 'evidence').length,
    riskCount: batch.items.filter((item) => item.kind === 'risk').length,
    appliedCount: batch.items.filter((item) => item.status === 'applied').length,
    conflictResolvedCount: batch.items.filter((item) => item.resolution).length,
    invalidatedRiskIds: [...historyInvalidated],
    atRevision: state.currentRevision,
  }
  batch.phase = 'completed'
  batch.completedAt = new Date().toISOString()
  batch.conclusion = conclusion
  return conclusion
}

export { kindLabel, itemKeyFor }
