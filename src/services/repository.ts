import type { ImportBatch, RiskAcceptanceRecord, ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const BATCHES_KEY = 'scapex-import-batches-v1'

const clone = <T>(value: T): T => structuredClone(value)

/** 兼容旧版本地状态：补齐风险接受台账并关联当前生效接受 */
const migrate = (state: ThreatModelState): ThreatModelState => {
  if (!Array.isArray(state.acceptances)) {
    const acceptances: RiskAcceptanceRecord[] = state.risks
      .filter((risk) => risk.status === 'accepted')
      .map((risk, index) => {
        const id = `acc-migrated-${index + 1}`
        risk.activeAcceptanceId = id
        return {
          id,
          riskId: risk.id,
          status: 'active',
          expiresAt: risk.acceptanceExpiresAt ?? '',
          condition: risk.acceptanceCondition ?? '历史接受（迁移补录）',
          actor: risk.owner,
          createdAt: new Date(0).toISOString(),
          basisFingerprint: '',
          source: 'manual',
        }
      })
    state.acceptances = acceptances
  }
  return state
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  try {
    return migrate(JSON.parse(raw) as ThreatModelState)
  } catch {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const loadBatches = (): ImportBatch[] => {
  const raw = localStorage.getItem(BATCHES_KEY)
  if (!raw) return []
  try {
    return JSON.parse(raw) as ImportBatch[]
  } catch {
    return []
  }
}

export const saveBatches = (batches: ImportBatch[]): void => {
  localStorage.setItem(BATCHES_KEY, JSON.stringify(clone(batches)))
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
