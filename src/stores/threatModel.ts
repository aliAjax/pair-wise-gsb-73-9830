import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  AcceptanceBasis,
  ActorRole,
  AuditEvent,
  DecisionType,
  ExchangeEntityKind,
  ExchangePackage,
  ImportBatch,
  Risk,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  armNextWriteFailure,
  clearCheckpoint,
  createId,
  discoverRecoverableBatch,
  loadCheckpoint,
  loadState,
  resetState,
  saveCheckpoint,
  saveState,
  StorageWriteError,
} from '@/services/repository'
import {
  applyPlanEntry,
  buildApplyPlan,
  createBatch as buildBatch,
  finalizeBatch,
  pendingConflicts,
  readyToApply,
  resolveItem,
} from '@/services/importBatch'
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

/** 打开页面时从检查点恢复的结果，用于在界面上提示续做 */
export interface RecoveryNotice {
  batchId: string
  label: string
  appliedCount: number
  totalCount: number
  savedAt: string
}

/** 写入批次应用阶段的进度事件 */
export interface ApplyProgress {
  done: number
  total: number
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())
  const recoveryNotice = ref<RecoveryNotice | null>(null)

  // 页面重开：若上次批次写入中断，整体装载完整检查点，等待续做
  const restoreCheckpointOnBoot = (): void => {
    const found = discoverRecoverableBatch(data.value)
    if (!found) return
    const { batch, checkpoint } = found
    data.value = checkpoint.state
    lastSavedAt.value = checkpoint.savedAt
    recoveryNotice.value = {
      batchId: batch.id,
      label: batch.label,
      appliedCount: checkpoint.appliedItemKeys.length,
      totalCount: batch.items.length,
      savedAt: checkpoint.savedAt,
    }
  }
  restoreCheckpointOnBoot()

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
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

  /**
   * 威胁或控制证据一变，关联风险上仍然有效的风险接受立即失效并重算。
   * 失效后原始接受条件/到期日保留（接受依据不删除），仅要求重新确认。
   */
  const invalidateAcceptancesByEntity = (kind: ExchangeEntityKind, entityId: string): Risk[] => {
    const state = data.value
    const controlIds =
      kind === 'evidence'
        ? new Set(
            state.controls
              .filter((control) => control.evidenceIds.includes(entityId))
              .map((control) => control.id),
          )
        : new Set<string>()

    const riskIds = new Set<string>()
    if (kind === 'threat') {
      state.threats
        .find((threat) => threat.id === entityId)
        ?.riskIds.forEach((id) => riskIds.add(id))
    } else if (kind === 'evidence') {
      state.threats.forEach((threat) => {
        if (threat.controlIds.some((id) => controlIds.has(id))) {
          threat.riskIds.forEach((id) => riskIds.add(id))
        }
      })
    }

    const nowIso = new Date().toISOString()
    const invalidated: Risk[] = []
    state.risks
      .filter(
        (risk) => riskIds.has(risk.id) && risk.status === 'accepted' && !risk.acceptanceInvalidatedAt,
      )
      .forEach((risk) => {
        const reason =
          kind === 'threat'
            ? `关联威胁 ${entityId} 发生本地修订，风险接受前提变化`
            : `支撑控制的证据 ${entityId} 发生本地修订，风险接受依据变化`
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
          createdAt: nowIso,
          createdBy: '系统（变更联动）',
        }
        state.acceptanceHistory.unshift(basis)
        appendAudit('risk', risk.id, '风险接受失效', reason)
        invalidated.push(risk)
      })
    return invalidated
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    // 威胁/证据更新立即联动失效风险接受（新增实体无关联，不触发）
    if (index >= 0 && (collection === 'threats' || collection === 'evidence')) {
      invalidateAcceptancesByEntity(collection === 'threats' ? 'threat' : 'evidence', item.id)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
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
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    const wasInvalidated = Boolean(risk.acceptanceInvalidatedAt)
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    // 重新确认：清除失效标记，但历史失效依据保留
    risk.acceptanceInvalidatedAt = undefined
    risk.acceptanceInvalidatedReason = undefined
    const basis: AcceptanceBasis = {
      id: createId('bas'),
      riskId: risk.id,
      riskCode: risk.code,
      type: wasInvalidated ? 'reconfirmed' : 'accepted',
      condition,
      expiresAt,
      reason: wasInvalidated ? '风险接受失效后人工重新评审确认' : '人工登记风险接受',
      createdAt: new Date().toISOString(),
      createdBy: '当前用户',
    }
    data.value.acceptanceHistory.unshift(basis)
    appendAudit(
      'risk',
      risk.id,
      wasInvalidated ? '重新确认风险接受' : '接受风险',
      `接受有效至 ${expiresAt}：${condition}`,
    )
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  // -------------------------------------------------------------------------
  // 交换包可恢复导入批次
  // -------------------------------------------------------------------------

  /** 建立批次：记住本地修订，与包内内容对账，冲突保留两版 */
  const openImportBatch = (pkg: ExchangePackage): ImportBatch => {
    const batch = buildBatch(data.value, pkg)
    data.value.importBatches.unshift(batch)
    appendAudit(
      'import_batch',
      batch.id,
      '创建导入批次',
      `${batch.label}：${batch.items.length} 条对账，${pendingConflicts(batch).length} 条冲突待确认`,
    )
    persist()
    return batch
  }

  const getBatch = (batchId: string): ImportBatch | undefined =>
    data.value.importBatches.find((batch) => batch.id === batchId)

  /** 冲突裁决：选择保留本地版或采用交换包版（两版始终留档） */
  const resolveImportItem = (
    batchId: string,
    itemKey: string,
    resolution: 'local' | 'package',
  ): void => {
    const batch = getBatch(batchId)
    if (!batch) return
    resolveItem(batch, itemKey, resolution, '当前用户')
    persist()
  }

  const abandonBatch = (batchId: string): void => {
    const batch = getBatch(batchId)
    if (!batch || batch.phase === 'completed') return
    batch.phase = 'abandoned'
    batch.lastError = null
    clearCheckpoint(batchId)
    recoveryNotice.value = null
    appendAudit('import_batch', batchId, '废弃导入批次', `${batch.label} 已人工废弃，未写入内容`)
    persist()
  }

  const armWriteFailure = (): void => {
    armNextWriteFailure()
  }

  const dismissRecoveryNotice = (): void => {
    recoveryNotice.value = null
  }

  /**
   * 应用（或从检查点续做）批次写入。
   * 每成功一条：先在内存更新，再写完整检查点（state + appliedItemKeys），
   * 最后提交主状态；任一步写入失败都停在最后一个完整检查点，可重入续做。
   * 重放时依据 appliedItemKeys 幂等跳过，不重复生成实体、审计与接受依据。
   */
  const applyImportBatch = async (
    batchId: string,
    onProgress?: (progress: ApplyProgress) => void,
  ): Promise<{ ok: boolean; error?: string }> => {
    const batch = getBatch(batchId)
    if (!batch) return { ok: false, error: '批次不存在' }
    if (!readyToApply(batch)) {
      return { ok: false, error: '仍有冲突未裁决' }
    }

    // 从检查点恢复内存位置（正常续做时与当前一致，页面重开后以此为准）
    const checkpoint = loadCheckpoint(batchId)
    let working: ThreatModelState = checkpoint ? structuredClone(checkpoint.state) : data.value
    const appliedItemKeys: string[] = checkpoint
      ? [...checkpoint.appliedItemKeys]
      : batch.items
          .filter((item) => item.status === 'applied' || item.status === 'skipped')
          .map((item) => item.itemKey)

    const workingBatch = working.importBatches.find((item) => item.id === batchId)
    if (!workingBatch) return { ok: false, error: '检查点中的批次已丢失' }

    // 幂等完成：检查点中已是完成态（上次只差主状态提交），只补提交，不再生成结论/审计
    if (workingBatch.phase === 'completed') {
      try {
        saveState(working)
      } catch (error) {
        const message = error instanceof Error ? error.message : '未知写入错误'
        data.value = working
        return { ok: false, error: message }
      }
      data.value = working
      lastSavedAt.value = new Date().toISOString()
      clearCheckpoint(batchId)
      recoveryNotice.value = null
      return { ok: true }
    }

    workingBatch.phase = 'applying'
    workingBatch.lastError = null

    const plan = buildApplyPlan(workingBatch)
    const total = plan.length
    /** 完整检查点落盘（独立存储键，不受主状态写入故障注入影响） */
    const checkpointWorking = (): void => {
      saveCheckpoint({
        batchId,
        savedAt: new Date().toISOString(),
        appliedItemKeys,
        state: working,
      })
    }

    for (const entry of plan) {
      if (appliedItemKeys.includes(entry.item.itemKey)) {
        onProgress?.({ done: appliedItemKeys.length, total })
        continue
      }

      const result = applyPlanEntry(working, workingBatch, entry, appliedItemKeys)
      working = result.state
      const refreshedBatch = working.importBatches.find((item) => item.id === batchId)
      if (!refreshedBatch) return { ok: false, error: '批次在写入过程中丢失' }

      try {
        appliedItemKeys.push(entry.item.itemKey)
        refreshedBatch.checkpoint = appliedItemKeys.length
        // 检查点包含本条应用后的完整状态；随后提交主状态
        checkpointWorking()
        saveState(working)
      } catch (error) {
        // 主状态提交失败，但上面的完整检查点已成功落盘（含本条）。
        // 仅在检查点状态上把批次标记为中断，续做时从该检查点之后继续。
        const checkpointState = structuredClone(working)
        const interruptedBatch = checkpointState.importBatches.find((item) => item.id === batchId)
        if (interruptedBatch) {
          interruptedBatch.phase = 'interrupted'
          interruptedBatch.lastError =
            error instanceof StorageWriteError ? error.message : '写入失败，已保留完整检查点'
        }
        saveCheckpoint({
          batchId,
          savedAt: new Date().toISOString(),
          appliedItemKeys,
          state: checkpointState,
        })
        const message = error instanceof Error ? error.message : '未知写入错误'
        data.value = checkpointState
        recoveryNotice.value = {
          batchId,
          label: batch.label,
          appliedCount: appliedItemKeys.length,
          totalCount: total,
          savedAt: new Date().toISOString(),
        }
        return { ok: false, error: message }
      }

      onProgress?.({ done: appliedItemKeys.length, total })
      // 让出事件循环，便于展示逐条写入进度
      await new Promise((resolve) => window.setTimeout(resolve, 120))
    }

    // 全部条目应用完毕：固化批次结论（版本差异与会签中心读取同一份）
    const finalBatch = working.importBatches.find((item) => item.id === batchId)
    if (!finalBatch) return { ok: false, error: '批次在完成时丢失' }
    finalizeBatch(working, finalBatch, [])
    working.audit.unshift({
      id: createId('aud'),
      entityType: 'import_batch',
      entityId: batchId,
      action: '完成导入批次',
      actor: '导入批次',
      createdAt: new Date().toISOString(),
      detail: `${finalBatch.label} 已完成：${finalBatch.conclusion?.appliedCount ?? 0} 条写入，${
        finalBatch.conclusion?.invalidatedRiskIds.length ?? 0
      } 条风险接受失效重算`,
    })

    // 结论先进入检查点；主状态提交若失败，续做会重新进入完成步骤
    saveCheckpoint({
      batchId,
      savedAt: new Date().toISOString(),
      appliedItemKeys,
      state: working,
    })
    try {
      saveState(working)
    } catch (error) {
      const interruptedState = structuredClone(working)
      const interruptedBatch = interruptedState.importBatches.find((item) => item.id === batchId)
      if (interruptedBatch) {
        interruptedBatch.phase = 'interrupted'
        interruptedBatch.lastError = '结论提交失败，可从检查点续做'
      }
      saveCheckpoint({
        batchId,
        savedAt: new Date().toISOString(),
        appliedItemKeys,
        state: interruptedState,
      })
      data.value = interruptedState
      const message = error instanceof Error ? error.message : '未知写入错误'
      return { ok: false, error: message }
    }

    data.value = working
    lastSavedAt.value = new Date().toISOString()
    clearCheckpoint(batchId)
    recoveryNotice.value = null
    return { ok: true }
  }

  const resetDemo = (): void => {
    data.value.importBatches.forEach((batch) => clearCheckpoint(batch.id))
    data.value = resetState()
    recoveryNotice.value = null
    lastSavedAt.value = new Date().toISOString()
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
      ...data.value.risks
        .filter((risk) => risk.acceptanceCondition || risk.status === 'accepted')
        .map((risk) => {
          const stateLabel = risk.acceptanceInvalidatedAt
            ? '【已失效待重算】'
            : risk.status === 'accepted'
              ? '【接受中】'
              : '【待重新确认】'
          return `- ${risk.code} ${risk.title} ${stateLabel}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`
        }),
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
    lastSavedAt,
    recoveryNotice,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    openImportBatch,
    getBatch,
    resolveImportItem,
    abandonBatch,
    applyImportBatch,
    armWriteFailure,
    dismissRecoveryNotice,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
