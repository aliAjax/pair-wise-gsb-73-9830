import type {
  ControlEvidence,
  RiskAcceptanceRecord,
  Threat,
  ThreatModelState,
} from '@/models/domain'

const canonical = (value: unknown): string => JSON.stringify(sortDeep(value))

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map(sortDeep)
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, sortDeep(item)]),
    )
  }
  return value
}

/** 与风险关联的威胁（threat.riskIds 反向关联） */
export const threatsForRisk = (state: ThreatModelState, riskId: string): Threat[] =>
  state.threats.filter((threat) => threat.riskIds.includes(riskId))

/** 威胁链路涉及的全部证据（通过 threat.controlIds 关联到控制的证据） */
export const evidenceForRisk = (
  state: ThreatModelState,
  riskId: string,
): ControlEvidence[] => {
  const controlIds = new Set(
    threatsForRisk(state, riskId).flatMap((threat) => threat.controlIds),
  )
  return state.evidence.filter((item) => {
    const control = state.controls.find((entry) => entry.id === item.controlId)
    return control ? controlIds.has(control.id) : false
  })
}

/**
 * 风险接受依据指纹：威胁内容 + 链路证据内容 + 控制集合。
 * 威胁或证据一变，指纹即与接受时不同，接受立即失效。
 */
export const riskBasisFingerprint = (state: ThreatModelState, riskId: string): string => {
  const threats = threatsForRisk(state, riskId).map((threat) => ({
    code: threat.code,
    title: threat.title,
    category: threat.category,
    description: threat.description,
    severity: threat.severity,
    status: threat.status,
    componentIds: threat.componentIds,
    flowIds: threat.flowIds,
    controlIds: threat.controlIds,
    riskIds: threat.riskIds,
    revision: threat.revision,
  }))
  const evidence = evidenceForRisk(state, riskId).map((item) => ({
    controlId: item.controlId,
    title: item.title,
    kind: item.kind,
    reference: item.reference,
    expiresAt: item.expiresAt,
    valid: item.valid,
  }))
  const controls = threatsForRisk(state, riskId).flatMap((threat) =>
    threat.controlIds.map((controlId) => {
      const control = state.controls.find((entry) => entry.id === controlId)
      return {
        controlId,
        status: control?.status ?? 'missing',
        evidenceIds: control?.evidenceIds ?? [],
      }
    }),
  )
  return canonical({ riskId, threats, evidence, controls })
}

export const buildBasisDetail = (
  state: ThreatModelState,
  riskId: string,
): RiskAcceptanceRecord['basisDetail'] => ({
  threatSummary: threatsForRisk(state, riskId).map((threat) => ({
    id: threat.id,
    code: threat.code,
    title: threat.title,
    revision: threat.revision,
  })),
  evidenceSummary: evidenceForRisk(state, riskId).map((item) => ({
    id: item.id,
    title: item.title,
    reference: item.reference,
    valid: item.valid,
    expiresAt: item.expiresAt,
  })),
})

export interface InvalidationResult {
  invalidated: RiskAcceptanceRecord[]
  reasons: Map<string, string>
}

/**
 * 检查全部生效接受：依据指纹与当前威胁/证据不符的立即失效。
 * 幂等：只处理 status=active 的记录，已失效记录及其依据原样保留。
 */
export const recomputeAcceptances = (state: ThreatModelState): InvalidationResult => {
  const invalidated: RiskAcceptanceRecord[] = []
  const reasons = new Map<string, string>()

  state.acceptances
    .filter((record) => record.status === 'active')
    .forEach((record) => {
      const risk = state.risks.find((item) => item.id === record.riskId)
      if (!risk || risk.status === 'closed') {
        record.status = 'invalidated'
        record.invalidatedAt = new Date().toISOString()
        record.invalidatedReason = '关联风险已关闭或删除'
        invalidated.push(record)
        reasons.set(record.id, record.invalidatedReason)
        if (risk) risk.activeAcceptanceId = undefined
        return
      }

      const current = riskBasisFingerprint(state, record.riskId)
      if (current !== record.basisFingerprint) {
        const threats = threatsForRisk(state, record.riskId)
        const evidence = evidenceForRisk(state, record.riskId)
        const changed = threats.length
          ? '关联威胁内容或修订已变化'
          : evidence.length
            ? '关联控制证据已变化'
            : '风险关联的威胁或证据已变化'
        record.status = 'invalidated'
        record.invalidatedAt = new Date().toISOString()
        record.invalidatedReason = changed
        invalidated.push(record)
        reasons.set(record.id, changed)
        risk.status = 'open'
        risk.acceptanceExpiresAt = undefined
        risk.acceptanceCondition = undefined
        risk.activeAcceptanceId = undefined
      }
    })

  return { invalidated, reasons }
}
