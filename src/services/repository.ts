import type {
  ImportBatch,
  ImportCheckpoint,
  ThreatModelState,
} from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const CHECKPOINT_PREFIX = 'scapex-import-checkpoint-'
/** 演示用：下一次状态写入将失败，用于验证检查点恢复 */
const FAIL_NEXT_KEY = 'scapex-fail-next-write'

const clone = <T>(value: T): T => structuredClone(value)

/** 兼容旧版本本地仓库：补齐导入批次与风险接受依据集合 */
const migrate = (state: ThreatModelState): ThreatModelState => {
  let changed = false
  if (!Array.isArray(state.importBatches)) {
    state.importBatches = []
    changed = true
  }
  if (!Array.isArray(state.acceptanceHistory)) {
    state.acceptanceHistory = []
    changed = true
  }
  return changed ? state : state
}

export class StorageWriteError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StorageWriteError'
  }
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

/**
 * 持久化主状态。若此前通过 armNextWriteFailure 设置了一次性写入失败，
 * 本次抛出 StorageWriteError 且不触碰已落盘内容（模拟写入失败）。
 */
export const saveState = (state: ThreatModelState): void => {
  if (localStorage.getItem(FAIL_NEXT_KEY) === '1') {
    localStorage.removeItem(FAIL_NEXT_KEY)
    throw new StorageWriteError('模拟的本地写入失败：存储层拒绝提交，请从检查点续做')
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

// ---------------------------------------------------------------------------
// 写入故障注入（演示恢复能力）
// ---------------------------------------------------------------------------

export const armNextWriteFailure = (): void => {
  localStorage.setItem(FAIL_NEXT_KEY, '1')
}

export const isWriteFailureArmed = (): boolean => localStorage.getItem(FAIL_NEXT_KEY) === '1'

// ---------------------------------------------------------------------------
// 完整检查点：主状态快照 + 已应用条目，单独键存储
// ---------------------------------------------------------------------------

export const checkpointKey = (batchId: string): string => `${CHECKPOINT_PREFIX}${batchId}`

export const saveCheckpoint = (checkpoint: ImportCheckpoint): void => {
  localStorage.setItem(checkpointKey(checkpoint.batchId), JSON.stringify(clone(checkpoint)))
}

export const loadCheckpoint = (batchId: string): ImportCheckpoint | null => {
  const raw = localStorage.getItem(checkpointKey(batchId))
  if (!raw) return null
  try {
    return JSON.parse(raw) as ImportCheckpoint
  } catch {
    return null
  }
}

export const clearCheckpoint = (batchId: string): void => {
  localStorage.removeItem(checkpointKey(batchId))
}

/** 打开页面时恢复：找到最近一个中断在 applying/interrupted 的批次及其检查点 */
export const discoverRecoverableBatch = (
  state: ThreatModelState,
): { batch: ImportBatch; checkpoint: ImportCheckpoint } | null => {
  const batch = [...state.importBatches]
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    .find((item) => item.phase === 'applying' || item.phase === 'interrupted')
  if (!batch) return null
  const checkpoint = loadCheckpoint(batch.id)
  if (!checkpoint) return null
  return { batch, checkpoint }
}
