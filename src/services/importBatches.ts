import type {
  ControlEvidence,
  ExchangeEvidence,
  ExchangePackage,
  ExchangeRiskAcceptance,
  ExchangeThreat,
  ImportBatch,
  ImportItem,
  Risk,
  RiskAcceptanceRecord,
  SecurityControl,
  Threat,
  ThreatModelState,
} from '@/models/domain'
import { createId } from '@/services/repository'
import { buildBasisDetail, recomputeAcceptances, riskBasisFingerprint } from '@/services/riskBasis'

/** 首次出现的外部标识映射为确定性本地 id */
const localIdFor = (kind: 'threat' | 'evidence', externalId: string): string =>
  `${kind === 'threat' ? 'thr' : 'ev'}-ext-${externalId}`

/**
 * 外部稳定标识到本地 id 的确定性映射：
 * 包内使用的标识若本地已存在（外部按本地 id 回传），直接对账同一条；
 * 否则首次导入映射为确定性的 ext id，重放同一包不会重复生成。
 */
const resolveThreatLocalId = (state: ThreatModelState, externalId: string): string =>
  state.threats.some((threat) => threat.id === externalId)
    ? externalId
    : localIdFor('threat', externalId)

const resolveEvidenceLocalId = (state: ThreatModelState, externalId: string): string =>
  state.evidence.some((evidence) => evidence.id === externalId)
    ? externalId
    : localIdFor('evidence', externalId)

const threatContentFields: (keyof ExchangeThreat)[] = [
  'code',
  'title',
  'category',
  'description',
  'severity',
  'status',
  'componentIds',
  'flowIds',
  'externalDependencyIds',
  'attackPathIds',
  'controlIds',
  'riskIds',
]

const evidenceContentFields: (keyof ExchangeEvidence)[] = [
  'controlId',
  'title',
  'kind',
  'reference',
  'collectedAt',
  'expiresAt',
  'owner',
  'valid',
]

const controlContentFields: (keyof SecurityControl)[] = [
  'name',
  'type',
  'status',
  'owner',
  'componentId',
  'description',
  'evidenceIds',
]

const differingFields = (a: Record<string, unknown>, b: Record<string, unknown>, fields: string[]): string[] =>
  fields.filter((field) => JSON.stringify(a[field]) !== JSON.stringify(b[field]))

const threatFromExchange = (incoming: ExchangeThreat, localId: string): Threat => ({
  id: localId,
  code: incoming.code,
  title: incoming.title,
  category: incoming.category,
  description: incoming.description,
  severity: incoming.severity,
  status: incoming.status,
  componentIds: incoming.componentIds,
  flowIds: incoming.flowIds,
  externalDependencyIds: incoming.externalDependencyIds,
  attackPathIds: incoming.attackPathIds,
  controlIds: incoming.controlIds,
  riskIds: incoming.riskIds,
  reviewStatus: 'in_review',
  revision: incoming.revision,
})

const evidenceFromExchange = (incoming: ExchangeEvidence, localId: string): ControlEvidence => ({
  id: localId,
  controlId: incoming.controlId,
  title: incoming.title,
  kind: incoming.kind,
  reference: incoming.reference,
  collectedAt: incoming.collectedAt,
  expiresAt: incoming.expiresAt,
  owner: incoming.owner,
  valid: incoming.valid,
})

const threatLabel = (threat: ExchangeThreat): string => `${threat.code} ${threat.title}`
const evidenceLabel = (evidence: ExchangeEvidence): string => evidence.title
const controlLabel = (control: SecurityControl): string => control.name
const acceptanceLabel = (riskId: string, state: ThreatModelState): string =>
  state.risks.find((risk) => risk.id === riskId)?.code ?? riskId

/** 建批次：保存导入前完整检查点，并与包内内容对账（此阶段不改主数据） */
export const createBatch = (state: ThreatModelState, pkg: ExchangePackage): ImportBatch => {
  const evidenceIdMap = new Map<string, string>()
  pkg.evidence.forEach((item) =>
    evidenceIdMap.set(item.externalId, resolveEvidenceLocalId(state, item.externalId)),
  )
  // 包内控制若引用外部证据 id，统一映射到本地确定性 id
  const remapControlEvidenceIds = (control: SecurityControl): SecurityControl => ({
    ...control,
    evidenceIds: control.evidenceIds.map((id) => evidenceIdMap.get(id) ?? id),
  })
  const items: ImportItem[] = []

  pkg.threats.forEach((incoming) => {
    const localId = resolveThreatLocalId(state, incoming.externalId)
    const local = state.threats.find((threat) => threat.id === localId)
    const localComparable: Record<string, unknown> | null = local
      ? { ...local }
      : null
    const incomingComparable = incoming as unknown as Record<string, unknown>
    const conflictFields = local
      ? differingFields(localComparable!, incomingComparable, threatContentFields as string[])
      : []
    const revisionClash = local ? local.revision !== incoming.revision : false
    const conflict = (conflictFields.length > 0 || revisionClash)
    items.push({
      key: `threat:${localId}`,
      kind: 'threat',
      externalKey: incoming.externalId,
      localId,
      label: threatLabel(incoming),
      status: conflict ? 'conflict' : local ? 'pending' : 'pending',
      localRevision: local?.revision ?? null,
      incomingRevision: incoming.revision,
      conflict,
      conflictFields: conflict
        ? [...conflictFields, ...(revisionClash && !conflictFields.includes('revision') ? ['revision'] : [])]
        : [],
      localVersion: local ? structuredClone(local) : null,
      incomingVersion: structuredClone(incoming),
      attempts: 0,
    })
  })

  pkg.evidence.forEach((incoming) => {
    const localId = resolveEvidenceLocalId(state, incoming.externalId)
    const local = state.evidence.find((item) => item.id === localId)
    const conflictFields = local
      ? differingFields(
          local as unknown as Record<string, unknown>,
          incoming as unknown as Record<string, unknown>,
          evidenceContentFields as string[],
        )
      : []
    items.push({
      key: `evidence:${localId}`,
      kind: 'evidence',
      externalKey: incoming.externalId,
      localId,
      label: evidenceLabel(incoming),
      status: conflictFields.length ? 'conflict' : 'pending',
      localRevision: null,
      incomingRevision: null,
      conflict: conflictFields.length > 0,
      conflictFields,
      localVersion: local ? structuredClone(local) : null,
      incomingVersion: structuredClone(incoming),
      attempts: 0,
    })
  })

  pkg.controls.forEach((rawControl) => {
    const incoming = remapControlEvidenceIds(rawControl)
    const local = state.controls.find((control) => control.id === incoming.id)
    const conflictFields = local
      ? differingFields(
          local as unknown as Record<string, unknown>,
          incoming as unknown as Record<string, unknown>,
          controlContentFields as string[],
        )
      : []
    items.push({
      key: `control:${incoming.id}`,
      kind: 'control',
      externalKey: incoming.id,
      localId: incoming.id,
      label: controlLabel(incoming),
      status: conflictFields.length ? 'conflict' : 'pending',
      localRevision: null,
      incomingRevision: null,
      conflict: conflictFields.length > 0,
      conflictFields,
      localVersion: local ? structuredClone(local) : null,
      incomingVersion: structuredClone(incoming),
      attempts: 0,
    })
  })

  pkg.riskAcceptances.forEach((incoming) => {
    const local = state.acceptances.find(
      (record) => record.riskId === incoming.riskId && record.status === 'active',
    )
    const conflictFields = local
      ? [
          ...(local.expiresAt !== incoming.expiresAt ? ['expiresAt'] : []),
          ...(local.condition !== incoming.condition ? ['condition'] : []),
        ]
      : []
    items.push({
      key: `acceptance:${incoming.riskId}`,
      kind: 'risk_acceptance',
      externalKey: incoming.riskId,
      localId: incoming.riskId,
      label: `风险接受 · ${acceptanceLabel(incoming.riskId, state)}`,
      status: conflictFields.length ? 'conflict' : 'pending',
      localRevision: null,
      incomingRevision: null,
      conflict: conflictFields.length > 0,
      conflictFields,
      localVersion: local ? structuredClone(local) : null,
      incomingVersion: structuredClone(incoming),
      attempts: 0,
    })
  })

  // 内容一致的条目直接标记为 identical，重放时跳过、不重复生成
  items.forEach((item) => {
    if (!item.conflict && item.localVersion && item.conflictFields.length === 0 && item.kind !== 'risk_acceptance') {
      item.status = 'identical'
    }
  })

  const batch: ImportBatch = {
    id: createId('batch'),
    packageId: pkg.packageId,
    packageName: pkg.packageName,
    sentBy: pkg.sentBy,
    sentAt: pkg.sentAt,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: 'reconciling',
    items,
    checkpoint: structuredClone(state),
    baseRevision: state.currentRevision,
    appliedRevision: null,
    invalidatedAcceptanceIds: [],
  }
  return batch
}

const applyThreat = (state: ThreatModelState, item: ImportItem): void => {
  const incoming = item.incomingVersion as ExchangeThreat
  const threat = threatFromExchange(incoming, item.localId)
  const index = state.threats.findIndex((entry) => entry.id === threat.id)
  if (index >= 0) {
    // 保留本地修订与审核流转，内容按批次结论覆盖；最终定稿时统一抬升修订
    threat.revision = state.threats[index].revision
    threat.reviewStatus = 'in_review'
    state.threats[index] = threat
  } else {
    state.threats.unshift(threat)
  }
}

const applyEvidence = (state: ThreatModelState, item: ImportItem): void => {
  const incoming = item.incomingVersion as ExchangeEvidence
  const evidence = evidenceFromExchange(incoming, item.localId)
  const control = state.controls.find((entry) => entry.id === evidence.controlId)
  const index = state.evidence.findIndex((entry) => entry.id === evidence.id)
  if (index >= 0) state.evidence[index] = evidence
  else state.evidence.unshift(evidence)
  if (control && !control.evidenceIds.includes(evidence.id)) {
    control.evidenceIds.push(evidence.id)
  }
}

const applyControl = (state: ThreatModelState, item: ImportItem): void => {
  const incoming = structuredClone(item.incomingVersion) as SecurityControl
  const index = state.controls.findIndex((entry) => entry.id === incoming.id)
  if (index >= 0) state.controls[index] = incoming
  else state.controls.unshift(incoming)
}

const acceptanceIdFor = (batchId: string, riskId: string): string =>
  `acc-imp-${batchId.replace(/[^a-z0-9]/gi, '')}-${riskId}`

const applyAcceptance = (
  state: ThreatModelState,
  batch: ImportBatch,
  item: ImportItem,
): void => {
  const incoming = item.incomingVersion as ExchangeRiskAcceptance
  const now = new Date().toISOString()

  // 威胁或证据一变，旧接受立即失效并保留依据，再按当前依据重算新接受
  const prior = state.acceptances.find((record) => record.riskId === incoming.riskId)
  if (prior && prior.status === 'active') {
    prior.status = 'invalidated'
    prior.invalidatedAt = now
    prior.invalidatedReason = '交换批次重算：依据威胁或证据已变化，以包内接受重新确认'
    if (!batch.invalidatedAcceptanceIds.includes(prior.id)) {
      batch.invalidatedAcceptanceIds.push(prior.id)
    }
  }

  const risk = state.risks.find((entry) => entry.id === incoming.riskId)
  const record: RiskAcceptanceRecord = {
    id: acceptanceIdFor(batch.id, incoming.riskId),
    riskId: incoming.riskId,
    status: 'active',
    expiresAt: incoming.expiresAt,
    condition: incoming.condition,
    actor: incoming.actor,
    createdAt: incoming.createdAt || now,
    basisFingerprint: riskBasisFingerprint(state, incoming.riskId),
    basisDetail: buildBasisDetail(state, incoming.riskId),
    source: 'import',
    sourceBatchId: batch.id,
    priorRecordId: prior?.id,
  }
  state.acceptances.unshift(record)
  if (risk) {
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = incoming.expiresAt
    risk.acceptanceCondition = incoming.condition
    risk.activeAcceptanceId = record.id
  }
}

/** 解析冲突时采用本地版：把包内版标记为已放弃，主数据保持本地内容 */
const keepLocalThreat = (state: ThreatModelState, item: ImportItem): void => {
  const local = structuredClone(item.localVersion) as Threat | null
  if (!local) return
  const index = state.threats.findIndex((entry) => entry.id === local.id)
  if (index >= 0) state.threats[index] = local
  else state.threats.unshift(local)
}
const keepLocalEvidence = (state: ThreatModelState, item: ImportItem): void => {
  const local = structuredClone(item.localVersion) as ControlEvidence | null
  if (!local) return
  const index = state.evidence.findIndex((entry) => entry.id === local.id)
  if (index >= 0) state.evidence[index] = local
  else state.evidence.unshift(local)
}
const keepLocalControl = (state: ThreatModelState, item: ImportItem): void => {
  const local = structuredClone(item.localVersion) as SecurityControl | null
  if (!local) return
  const index = state.controls.findIndex((entry) => entry.id === local.id)
  if (index >= 0) state.controls[index] = local
  else state.controls.unshift(local)
}
const keepLocalAcceptance = (state: ThreatModelState, item: ImportItem): void => {
  // 保留本地已确认接受（含依据），包内接受不写入
  const local = item.localVersion as RiskAcceptanceRecord | null
  if (!local) {
    // 本地无接受而选择保留本地：不接受该风险，维持开放
    const risk = state.risks.find((entry) => entry.id === item.localId)
    if (risk && risk.status === 'accepted') {
      risk.status = 'open'
      risk.acceptanceExpiresAt = undefined
      risk.acceptanceCondition = undefined
      risk.activeAcceptanceId = undefined
    }
  }
  void state
}

const applyIncomingItem = (state: ThreatModelState, batch: ImportBatch, item: ImportItem): void => {
  if (item.kind === 'threat') applyThreat(state, item)
  else if (item.kind === 'evidence') applyEvidence(state, item)
  else if (item.kind === 'control') applyControl(state, item)
  else applyAcceptance(state, batch, item)
}

const keepLocalItem = (state: ThreatModelState, item: ImportItem): void => {
  if (item.kind === 'threat') keepLocalThreat(state, item)
  else if (item.kind === 'evidence') keepLocalEvidence(state, item)
  else if (item.kind === 'control') keepLocalControl(state, item)
  else keepLocalAcceptance(state, item)
}

export interface ApplyOutcome {
  batch: ImportBatch
  /** 是否仍有条目待确认 */
  awaitingConfirmation: boolean
  failedItem?: ImportItem
}

const orderedPendingItems = (batch: ImportBatch): ImportItem[] => [
  ...batch.items.filter((item) => item.kind !== 'risk_acceptance'),
  ...batch.items.filter((item) => item.kind === 'risk_acceptance'),
]

/**
 * 应用所有 pending 条目，按 resolution 决定版本（确认后重放与首次应用共用此路径）。
 * 每个条目一次提交（主数据 + 批次），写失败时标记批次并抛出，由调用方从检查点恢复。
 */
const applyPendingItems = (
  state: ThreatModelState,
  batch: ImportBatch,
  commit: (state: ThreatModelState, batch: ImportBatch) => void,
): { remainingConflicts: boolean } => {
  const failItem = (item: ImportItem, error: unknown): never => {
    item.status = 'failed'
    item.lastError = error instanceof Error ? error.message : String(error)
    batch.status = 'failed'
    batch.lastError = item.lastError
    batch.updatedAt = new Date().toISOString()
    // 尽力持久化失败标记；即使仍失败，内存批次也已带 failed 供本次会话续做
    try {
      commit(state, batch)
    } catch {
      // 忽略二次写入失败
    }
    throw error instanceof Error ? error : new Error(String(error))
  }

  for (const item of orderedPendingItems(batch)) {
    if (item.kind === 'risk_acceptance') break
    if (item.status === 'conflict') continue
    if (item.status !== 'pending') continue

    item.attempts += 1
    try {
      if (item.resolution === 'local') {
        keepLocalItem(state, item)
      } else {
        applyIncomingItem(state, batch, item)
      }
      commit(state, batch)
      item.status = item.resolution ? 'resolution_applied' : 'applied'
      item.conflict = false
      item.lastError = undefined
      commit(state, batch)
    } catch (error) {
      failItem(item, error)
    }
  }

  // 威胁或证据一变，风险接受立即失效重算；失效记录依据完整保留
  const { invalidated } = recomputeAcceptances(state)
  invalidated.forEach((record) => {
    if (!batch.invalidatedAcceptanceIds.includes(record.id)) {
      batch.invalidatedAcceptanceIds.push(record.id)
    }
  })

  for (const item of orderedPendingItems(batch)) {
    if (item.kind !== 'risk_acceptance') continue
    if (item.status === 'conflict') continue
    if (item.status !== 'pending') continue

    item.attempts += 1
    try {
      if (item.resolution === 'local') {
        keepLocalItem(state, item)
      } else {
        applyIncomingItem(state, batch, item)
      }
      commit(state, batch)
      item.status = item.resolution ? 'resolution_applied' : 'applied'
      item.conflict = false
      item.lastError = undefined
      commit(state, batch)
    } catch (error) {
      failItem(item, error)
    }
  }

  return {
    remainingConflicts: batch.items.some((item) => item.status === 'conflict'),
  }
}

/**
 * 应用所有无需确认的 pending 条目（幂等：applied/identical 跳过）。
 */
export const advanceBatch = (
  state: ThreatModelState,
  batch: ImportBatch,
  commit: (state: ThreatModelState, batch: ImportBatch) => void,
): ApplyOutcome => {
  if (batch.status === 'completed' || batch.status === 'discarded') {
    return { batch, awaitingConfirmation: false }
  }

  const hasConflicts = batch.items.some((item) => item.status === 'conflict')
  batch.status = hasConflicts ? 'awaiting_confirmation' : 'applying'
  batch.updatedAt = new Date().toISOString()
  commit(state, batch)

  const result = applyPendingItems(state, batch, commit)

  if (result.remainingConflicts) {
    batch.status = 'awaiting_confirmation'
    batch.updatedAt = new Date().toISOString()
    commit(state, batch)
    return { batch, awaitingConfirmation: true }
  }

  finalizeBatch(state, batch, commit)
  return { batch, awaitingConfirmation: false }
}

/** 冲突逐条确认（两版任选），确认后该条目结论不可变 */
export const resolveConflict = (
  state: ThreatModelState,
  batch: ImportBatch,
  itemKey: string,
  resolution: 'local' | 'incoming',
  actor: string,
  commit: (state: ThreatModelState, batch: ImportBatch) => void,
): ApplyOutcome => {
  const item = batch.items.find((entry) => entry.key === itemKey)
  if (!item || item.status !== 'conflict') {
    return { batch, awaitingConfirmation: batch.items.some((entry) => entry.status === 'conflict') }
  }

  item.resolution = resolution
  item.resolutionActor = actor
  item.resolutionAt = new Date().toISOString()
  item.status = 'pending'

  const result = applyPendingItems(state, batch, commit)

  if (result.remainingConflicts) {
    batch.status = 'awaiting_confirmation'
    batch.updatedAt = new Date().toISOString()
    commit(state, batch)
    return { batch, awaitingConfirmation: true }
  }

  finalizeBatch(state, batch, commit)
  return { batch, awaitingConfirmation: false }
}
/** 从完整检查点续做：恢复主数据到检查点，再幂等重放全部已确认结论 */
export const resumeBatch = (
  batch: ImportBatch,
  commit: (state: ThreatModelState, batch: ImportBatch) => void,
): ApplyOutcome => {
  if (!batch.checkpoint) {
    batch.status = 'failed'
    batch.lastError = '缺少完整检查点，无法恢复'
    commit({} as ThreatModelState, batch)
    return { batch, awaitingConfirmation: false }
  }

  const state = structuredClone(batch.checkpoint)
  batch.status = 'resuming'
  batch.invalidatedAcceptanceIds = []
  // 已确认/已应用的条目按结论重放；未确认的保持 conflict；一致项跳过
  batch.items = batch.items.map((item) => {
    if (item.status === 'identical' || item.status === 'conflict') return item
    return { ...item, status: 'pending', lastError: undefined, conflict: false }
  })
  batch.updatedAt = new Date().toISOString()
  commit(state, batch)

  const result = applyPendingItems(state, batch, commit)
  if (result.remainingConflicts) {
    batch.status = 'awaiting_confirmation'
    batch.updatedAt = new Date().toISOString()
    commit(state, batch)
    return { batch, awaitingConfirmation: true }
  }
  finalizeBatch(state, batch, commit)
  return { batch, awaitingConfirmation: false }
}

/** 放弃批次：主数据恢复到导入前检查点，批次留档为 discarded */
export const discardBatch = (
  batch: ImportBatch,
  commitBatchOnly: (batch: ImportBatch) => void,
): ThreatModelState => {
  const state = structuredClone(batch.checkpoint) as ThreatModelState
  batch.status = 'discarded'
  batch.updatedAt = new Date().toISOString()
  commitBatchOnly(batch)
  return state
}

/** 定稿：抬升修订、生成与批次结论一一对应的版本快照 */
const finalizeBatch = (
  state: ThreatModelState,
  batch: ImportBatch,
  commit: (state: ThreatModelState, batch: ImportBatch) => void,
): void => {
  const revision = state.currentRevision + 1
  const changedThreatKeys = new Set(
    batch.items
      .filter(
        (item) =>
          item.kind === 'threat' &&
          (item.status === 'applied' || item.status === 'resolution_applied'),
      )
      .map((item) => item.localId),
  )
  const affectedThreatIds = state.threats
    .filter((threat) => changedThreatKeys.has(threat.id))
    .map((threat) => threat.id)

  // 证据或控制变化波及到的威胁也进入重新会签
  const affectedControlIds = new Set(
    batch.items
      .filter(
        (item) =>
          (item.kind === 'control' || item.kind === 'evidence') &&
          (item.status === 'applied' || item.status === 'resolution_applied'),
      )
      .map((item) => (item.kind === 'evidence' ? (item.incomingVersion as ExchangeEvidence).controlId : item.localId)),
  )
  state.threats.forEach((threat) => {
    if (threat.controlIds.some((id) => affectedControlIds.has(id)) && !affectedThreatIds.includes(threat.id)) {
      affectedThreatIds.push(threat.id)
    }
  })

  state.threats.forEach((threat) => {
    if (affectedThreatIds.includes(threat.id)) {
      threat.revision = revision
      threat.reviewStatus = 'in_review'
    }
  })
  state.currentRevision = revision

  const conclusion = {
    batchId: batch.id,
    packageName: batch.packageName,
    reconciledAt: new Date().toISOString(),
    incoming: batch.items.length,
    applied: batch.items.filter((item) => ['applied', 'resolution_applied'].includes(item.status)).length,
    conflicts: batch.items.filter((item) => item.resolution).length,
    skipped: batch.items.filter((item) => item.status === 'identical').length,
    invalidatedAcceptances: [...batch.invalidatedAcceptanceIds],
  }

  const version = {
    id: createId('ver'),
    revision,
    label: `${batch.packageName}（交换导入）`,
    createdAt: new Date().toISOString(),
    author: batch.sentBy,
    notes: `外部评估组交换包 ${batch.packageId} 导入定稿：新增/更新 ${conclusion.applied} 项，冲突双版确认 ${conclusion.conflicts} 项，一致跳过 ${conclusion.skipped} 项。`,
    threatIds: state.threats.map((threat) => threat.id),
    componentIds: state.components.map((component) => component.id),
    flowIds: state.flows.map((flow) => flow.id),
    controlIds: state.controls.map((control) => control.id),
    riskIds: state.risks.map((risk) => risk.id),
    affectedThreatIds,
    sourceBatchId: batch.id,
    batchConclusion: conclusion,
  }
  state.versions.unshift(version)

  // 确定性审计事件：重放时按 id 去重，不重复生成
  const auditId = `aud-${batch.id.replace(/[^a-z0-9]/gi, '')}-finalize`
  if (!state.audit.some((event) => event.id === auditId)) {
    state.audit.unshift({
      id: auditId,
      entityType: 'import_batch',
      entityId: batch.id,
      action: '交换包导入定稿',
      actor: batch.sentBy,
      createdAt: new Date().toISOString(),
      detail: `${batch.packageName}：应用 ${conclusion.applied} 项，冲突确认 ${conclusion.conflicts} 项，失效风险接受 ${conclusion.invalidatedAcceptances.length} 条。`,
    })
  }

  batch.status = 'completed'
  batch.appliedRevision = revision
  batch.versionId = version.id
  batch.conclusion = conclusion
  batch.updatedAt = new Date().toISOString()
  commit(state, batch)
}

/** 未关联任何条目（供 UI 展示） */
export const describeRisk = (state: ThreatModelState, riskId: string): Risk | undefined =>
  state.risks.find((risk) => risk.id === riskId)
