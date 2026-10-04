import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  ConflictResolution,
  DecisionType,
  ExchangePackage,
  ImportBatch,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  createId,
  loadBatches,
  loadState,
  resetState,
  saveBatches,
  saveState,
} from '@/services/repository'
import {
  advanceBatch,
  createBatch,
  discardBatch,
  resolveConflict,
  resumeBatch,
} from '@/services/importBatches'
import { buildBasisDetail, recomputeAcceptances, riskBasisFingerprint } from '@/services/riskBasis'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

const ACTIVE_BATCH_STATES = ['reconciling', 'awaiting_confirmation', 'applying', 'failed', 'resuming']

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const batches = ref<ImportBatch[]>(loadBatches())
  const lastSavedAt = ref(new Date().toISOString())
  /** 演示/演练用：让下一次写入失败，验证从检查点恢复 */
  const failNextWrite = ref(false)
  const lastWriteError = ref<string | null>(null)

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )
  const activeBatch = computed(
    () => batches.value.find((batch) => ACTIVE_BATCH_STATES.includes(batch.status)) ?? null,
  )
  const hasActiveBatch = computed(() => activeBatch.value !== null)

  const persist = (): void => {
    if (failNextWrite.value) {
      failNextWrite.value = false
      throw new Error('模拟写入失败：存储不可用（用于演练检查点恢复）')
    }
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  /** 批次引擎提交：主数据与批次日志一次提交；失败后从最近成功持久化恢复内存态 */
  const commitBatch = (state: ThreatModelState, batch: ImportBatch): void => {
    if (failNextWrite.value) {
      failNextWrite.value = false
      throw new Error('模拟写入失败：存储不可用（用于演练检查点恢复）')
    }
    saveState(state)
    const stored = loadBatches()
    const next = stored.map((entry) => (entry.id === batch.id ? batch : entry))
    if (!next.some((entry) => entry.id === batch.id)) next.unshift(batch)
    saveBatches(next)
  }

  const refreshBatches = (): void => {
    batches.value = loadBatches()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  /** 本地内容变更后重算风险接受：威胁或证据一变，生效接受立即失效（依据保留） */
  const invalidateStaleAcceptances = (sourceDetail: string): string[] => {
    const { invalidated } = recomputeAcceptances(data.value)
    invalidated.forEach((record) => {
      appendAudit(
        'risk',
        record.riskId,
        '风险接受失效',
        `${sourceDetail}：${record.invalidatedReason ?? '依据已变化'}（原接受 ${record.id} 依据保留）`,
      )
    })
    return invalidated.map((record) => record.id)
  }

  const guardActiveBatch = (): boolean => hasActiveBatch.value

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    if (guardActiveBatch()) return
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    if (collection === 'threats' || collection === 'evidence' || collection === 'controls') {
      invalidateStaleAcceptances(
        collection === 'threats' ? '威胁内容修订' : collection === 'evidence' ? '控制证据变更' : '控制状态变更',
      )
    }
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    if (guardActiveBatch()) return
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    if (collection === 'threats' || collection === 'evidence' || collection === 'controls') {
      invalidateStaleAcceptances(
        collection === 'threats' ? '威胁移除' : collection === 'evidence' ? '证据移除' : '控制移除',
      )
    }
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    if (guardActiveBatch()) return
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    persist()
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
    const requiredRoles: ActorRole[] = ['development', 'security', 'business']
    const allSubmitted = requiredRoles.every((requiredRole) =>
      currentDecisions.some((item) => item.role === requiredRole),
    )
    if (currentDecisions.some((item) => item.decision === 'rejected')) {
      threat.reviewStatus = 'rejected'
    } else if (
      allSubmitted &&
      currentDecisions.every((item) => item.decision === 'approved')
    ) {
      threat.reviewStatus = 'approved'
    } else {
      threat.reviewStatus = 'in_review'
    }

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    persist()
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    if (guardActiveBatch()) return
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return

    const prior = data.value.acceptances.find(
      (record) => record.riskId === riskId && record.status === 'active',
    )
    if (prior) {
      prior.status = 'invalidated'
      prior.invalidatedAt = new Date().toISOString()
      prior.invalidatedReason = '重新登记风险接受，旧接受归档并保留依据'
    }

    const record = {
      id: createId('acc'),
      riskId,
      status: 'active' as const,
      expiresAt,
      condition,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      basisFingerprint: riskBasisFingerprint(data.value, riskId),
      basisDetail: buildBasisDetail(data.value, riskId),
      source: 'manual' as const,
      priorRecordId: prior?.id,
    }
    data.value.acceptances.unshift(record)
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    risk.activeAcceptanceId = record.id
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    if (guardActiveBatch()) return
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    invalidateStaleAcceptances('风险关闭')
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  /* ============ 交换包导入批次 ============ */

  const snapshot = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

  /** 引擎执行后统一从持久化层回读，保证内存态 == 最近成功写入态 */
  const reloadFromStorage = (): void => {
    data.value = loadState()
    batches.value = loadBatches()
    lastSavedAt.value = new Date().toISOString()
  }

  const runEngine = (worker: () => void): boolean => {
    try {
      worker()
      lastWriteError.value = null
      reloadFromStorage()
      return true
    } catch (error) {
      lastWriteError.value = error instanceof Error ? error.message : String(error)
      reloadFromStorage()
      return false
    }
  }

  const startImport = (pkg: ExchangePackage): ImportBatch | null => {
    if (guardActiveBatch()) return activeBatch.value
    const state = snapshot(data.value)
    // 批次创建时先与包内内容对账，并把完整检查点落盘（与主数据分离）
    const batch = createBatch(state, pkg)
    try {
      saveBatches([batch, ...batches.value])
    } catch (error) {
      lastWriteError.value = error instanceof Error ? error.message : String(error)
      return null
    }
    runEngine(() => advanceBatch(state, batch, commitBatch))
    return batches.value.find((entry) => entry.id === batch.id) ?? batch
  }

  const resolveImportConflict = (itemKey: string, resolution: ConflictResolution): void => {
    const live = activeBatch.value
    if (!live) return
    const state = snapshot(data.value)
    const batch = snapshot(live)
    runEngine(() =>
      resolveConflict(state, batch, itemKey, resolution, '当前用户', commitBatch),
    )
  }

  const resumeImport = (): void => {
    const live = activeBatch.value
    if (!live) return
    const batch = snapshot(live)
    // 从检查点恢复时，引擎以检查点内的完整主数据为基准幂等重放
    runEngine(() => resumeBatch(batch, commitBatch))
  }

  const discardImport = (): void => {
    const live = activeBatch.value
    if (!live) return
    const batch = snapshot(live)
    const restored = discardBatch(batch, (updated) => {
      const next = loadBatches().map((entry) => (entry.id === updated.id ? updated : entry))
      saveBatches(next)
    })
    saveState(restored)
    lastWriteError.value = null
    reloadFromStorage()
  }

  const armWriteFailure = (): void => {
    failNextWrite.value = true
  }

  /** 页面重开时自动续做：把未完成批次从检查点恢复（冲突待确认的批次保持等待） */
  const resumeOnLoad = (): void => {
    const batch = activeBatch.value
    if (!batch) return
    if (batch.status === 'awaiting_confirmation' || batch.status === 'reconciling') return
    resumeImport()
  }

  const resetDemo = (): void => {
    const seed = resetState()
    saveBatches([])
    data.value = seed
    batches.value = []
    lastSavedAt.value = new Date().toISOString()
    lastWriteError.value = null
  }

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.acceptances
        .map((record) => ({
          record,
          risk: data.value.risks.find((risk) => risk.id === record.riskId),
        }))
        .map(
          ({ record, risk }) =>
            `- [${record.status === 'active' ? '生效' : '已失效'}] ${risk?.code ?? record.riskId} ${risk?.title ?? ''}，` +
            `有效至 ${record.expiresAt}，条件：${record.condition}，依据威胁 ${record.basisDetail?.threatSummary.map((item) => item.code).join('、') || '无'}` +
            `${record.invalidatedReason ? `；失效原因：${record.invalidatedReason}` : ''}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    batches,
    lastSavedAt,
    lastWriteError,
    metrics,
    issues,
    pendingReviews,
    activeBatch,
    hasActiveBatch,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    startImport,
    resolveImportConflict,
    resumeImport,
    discardImport,
    armWriteFailure,
    resumeOnLoad,
    refreshBatches,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
