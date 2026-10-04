import type {
  AcceptanceBasis,
  BatchConclusion,
  ControlEvidence,
  ImportBatch,
  ReviewDecision,
  Risk,
  Severity,
  Threat,
  ThreatModelState,
  ValidationIssue,
  VersionDifference,
  VersionSnapshot,
} from '@/models/domain'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const riskScore = (risk: Risk): number => risk.likelihood * risk.impact

export const riskLevel = (score: number): Severity => {
  if (score >= 20) return 'critical'
  if (score >= 12) return 'high'
  if (score >= 6) return 'medium'
  return 'low'
}

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

/**
 * 风险接受是否仍然成立：威胁或证据一变即被判定失效（acceptanceInvalidatedAt），
 * 即使未到期也不再算作有效接受，需要重新评审确认。
 */
export const isRiskAcceptanceActive = (risk: Risk): boolean =>
  risk.status === 'accepted' &&
  !risk.acceptanceInvalidatedAt &&
  !isExpired(risk.acceptanceExpiresAt)

/** 当前风险接受的依据（最近一次接受/重新确认/失效留痕） */
export const acceptanceBasisFor = (
  history: AcceptanceBasis[],
  riskId: string,
): AcceptanceBasis | null => history.find((basis) => basis.riskId === riskId) ?? null

export const getValidationIssues = (state: ThreatModelState): ValidationIssue[] => {
  const issues: ValidationIssue[] = []
  const coveredComponentIds = new Set(state.threats.flatMap((threat) => threat.componentIds))
  const coveredFlowIds = new Set(state.threats.flatMap((threat) => threat.flowIds))

  state.components
    .filter((component) => !coveredComponentIds.has(component.id))
    .forEach((component) => {
      issues.push({
        id: `coverage-component-${component.id}`,
        kind: 'uncovered_component',
        severity: component.criticality,
        title: `${component.name} 尚无关联威胁`,
        detail: '该组件位于建模边界内，但当前威胁清单没有覆盖它。',
        entityId: component.id,
      })
    })

  state.flows
    .filter((flow) => !coveredFlowIds.has(flow.id))
    .forEach((flow) => {
      issues.push({
        id: `coverage-flow-${flow.id}`,
        kind: 'uncovered_component',
        severity: flow.crossesTrustBoundary ? 'high' : 'medium',
        title: `${flow.name} 尚无关联威胁`,
        detail: '该数据流未进入威胁分析，请确认是否需要补充威胁场景。',
        entityId: flow.id,
      })
    })

  state.controls
    .filter((control) => control.status === 'failed' || control.status === 'degraded')
    .forEach((control) => {
      issues.push({
        id: `control-${control.id}`,
        kind: 'control_failed',
        severity: control.status === 'failed' ? 'critical' : 'high',
        title: `${control.name} 控制${control.status === 'failed' ? '已失效' : '能力降级'}`,
        detail: '控制状态低于设计目标，相关缓解措施必须重新验证。',
        entityId: control.id,
      })
    })

  state.controls
    .filter((control) => {
      if (control.evidenceIds.length === 0) return true
      const validEvidence = control.evidenceIds
        .map((id) => state.evidence.find((item) => item.id === id))
        .filter((item): item is ControlEvidence => Boolean(item))
        .filter((item) => item.valid && !evidenceIsExpired(item))
      return validEvidence.length === 0
    })
    .forEach((control) => {
      issues.push({
        id: `evidence-${control.id}`,
        kind: 'missing_evidence',
        severity: control.status === 'planned' ? 'medium' : 'high',
        title: `${control.name} 缺少有效证据`,
        detail: '未找到未过期且状态有效的控制证据，暂不能判定控制持续有效。',
        entityId: control.id,
      })
    })

  state.risks
    .filter((risk) => risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt))
    .forEach((risk) => {
      issues.push({
        id: `expired-${risk.id}`,
        kind: 'risk_acceptance_expired',
        severity: riskLevel(riskScore(risk)),
        title: `${risk.code} 风险接受已过期`,
        detail: `接受到期日为 ${risk.acceptanceExpiresAt ?? '未设置'}，需要重新评审或转为处置。`,
        entityId: risk.id,
      })
    })

  state.risks
    .filter((risk) => Boolean(risk.acceptanceInvalidatedAt))
    .forEach((risk) => {
      issues.push({
        id: `invalidated-acceptance-${risk.id}`,
        kind: 'risk_acceptance_invalidated',
        severity: riskLevel(riskScore(risk)),
        title: `${risk.code} 风险接受已失效待重算`,
        detail: risk.acceptanceInvalidatedReason ?? '关联威胁或控制证据发生变更，接受前提不再成立。',
        entityId: risk.id,
      })
    })

  const taskGroups = new Map<string, typeof state.mitigations>()
  state.mitigations.forEach((task) => {
    if (!task.conflictGroup) return
    const key = `${task.threatId}:${task.conflictGroup}`
    const group = taskGroups.get(key) ?? []
    group.push(task)
    taskGroups.set(key, group)
  })

  taskGroups.forEach((tasks) => {
    const actions = new Set(tasks.map((task) => task.action))
    const hasAllow = actions.has('allow_with_condition')
    const hasRestrictiveAction = actions.has('restrict') || actions.has('isolate')
    if (hasAllow && hasRestrictiveAction) {
      issues.push({
        id: `conflict-${tasks[0]?.conflictGroup ?? 'unknown'}`,
        kind: 'mitigation_conflict',
        severity: 'high',
        title: '缓解措施处置方向冲突',
        detail: tasks.map((task) => task.title).join('；'),
        entityId: tasks[0]?.threatId ?? '',
      })
    }
  })

  return issues.sort((a, b) => {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    return rank[b.severity] - rank[a.severity]
  })
}

export const decisionsForThreat = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  decisions.filter((decision) => decision.threatId === threatId && decision.revision === revision)

export const reviewProgress = (decisions: ReviewDecision[]): number => {
  const roles = new Set(decisions.map((decision) => decision.role))
  return Math.round((roles.size / 3) * 100)
}

export const compareSnapshots = (from: VersionSnapshot, to: VersionSnapshot): VersionDifference => {
  const compare = (
    category: string,
    before: string[],
    after: string[],
  ): { added: VersionDifference['added']; removed: VersionDifference['removed'] } => {
    const beforeSet = new Set(before)
    const afterSet = new Set(after)
    return {
      added: after.filter((id) => !beforeSet.has(id)).map((id) => ({ category, id })),
      removed: before.filter((id) => !afterSet.has(id)).map((id) => ({ category, id })),
    }
  }

  const componentDiff = compare('组件', from.componentIds, to.componentIds)
  const flowDiff = compare('数据流', from.flowIds, to.flowIds)
  const threatDiff = compare('威胁', from.threatIds, to.threatIds)
  const controlDiff = compare('控制', from.controlIds, to.controlIds)
  const riskDiff = compare('风险', from.riskIds, to.riskIds)
  const affectedBefore = new Set(from.affectedThreatIds)
  const affectedAfter = new Set(to.affectedThreatIds)

  return {
    added: [
      ...componentDiff.added,
      ...flowDiff.added,
      ...threatDiff.added,
      ...controlDiff.added,
      ...riskDiff.added,
    ],
    removed: [
      ...componentDiff.removed,
      ...flowDiff.removed,
      ...threatDiff.removed,
      ...controlDiff.removed,
      ...riskDiff.removed,
    ],
    changed: [
      `受影响威胁：${from.affectedThreatIds.length} → ${to.affectedThreatIds.length}`,
      `新增进入审核：${[...affectedAfter].filter((id) => !affectedBefore.has(id)).join('、') || '无'}`,
      `退出审核：${[...affectedBefore].filter((id) => !affectedAfter.has(id)).join('、') || '无'}`,
      `版本说明：${to.notes || '未填写'}`,
    ],
  }
}

export const threatCoverage = (state: ThreatModelState): number => {
  if (state.components.length === 0) return 100
  const covered = new Set(state.threats.flatMap((threat) => threat.componentIds))
  return Math.round((covered.size / state.components.length) * 100)
}

export const openCriticalThreats = (threats: Threat[]): number =>
  threats.filter((threat) => threat.severity === 'critical' && threat.status !== 'mitigated').length

export interface DashboardMetrics {
  components: number
  threats: number
  critical: number
  coverage: number
  openIssues: number
  pendingReviews: number
}

export const dashboardMetrics = (state: ThreatModelState): DashboardMetrics => ({
  components: state.components.length,
  threats: state.threats.length,
  critical: openCriticalThreats(state.threats),
  coverage: threatCoverage(state),
  openIssues: getValidationIssues(state).length,
  pendingReviews: state.threats.filter((threat) => threat.reviewStatus === 'in_review').length,
})

// ---------------------------------------------------------------------------
// 导入批次：版本差异页与会签中心读取同一批次结论（唯一事实来源）
// ---------------------------------------------------------------------------

/** 当前活动的导入批次（未完成的最近批次优先），没有则回退到最近完成批次 */
export const activeImportBatch = (state: ThreatModelState): ImportBatch | null => {
  const ordered = [...state.importBatches].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
  return (
    ordered.find(
      (batch) => batch.phase === 'reconciling' || batch.phase === 'interrupted' || batch.phase === 'applying',
    ) ??
    ordered.find((batch) => batch.phase === 'completed' && batch.conclusion) ??
    null
  )
}

/**
 * 两个页面共用的批次结论。优先读取批次完成时固化的结论；
 * 进行中的批次则实时计算（不写回），保证打开任意页面看到的是同一口径。
 */
export const batchConclusion = (batch: ImportBatch | null): BatchConclusion | null => {
  if (!batch) return null
  if (batch.conclusion) return batch.conclusion
  const applied = batch.items.filter((item) => item.status === 'applied')
  return {
    threatIds: [...new Set(applied.filter((item) => item.kind === 'threat').map((item) => item.entityId))],
    threatCount: batch.items.filter((item) => item.kind === 'threat').length,
    evidenceCount: batch.items.filter((item) => item.kind === 'evidence').length,
    riskCount: batch.items.filter((item) => item.kind === 'risk').length,
    appliedCount: applied.length,
    conflictResolvedCount: batch.items.filter((item) => item.resolution).length,
    invalidatedRiskIds: [],
    atRevision: batch.baseRevision,
  }
}

/** 会签中心据此限定范围：批次结论中实际应用的威胁；无批次时回退版本逻辑 */
export const reviewThreatIdsFromBatch = (
  state: ThreatModelState,
  batch: ImportBatch | null,
): string[] | null => {
  const conclusion = batchConclusion(batch)
  if (!conclusion) return null
  // 只保留当前仍存在于模型中的威胁
  const present = new Set(state.threats.map((threat) => threat.id))
  return conclusion.threatIds.filter((id) => present.has(id))
}
