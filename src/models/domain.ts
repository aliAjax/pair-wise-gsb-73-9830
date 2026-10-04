export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
  /** 最近一次风险接受被威胁/证据变更判定失效的时间；失效后必须重算重提 */
  acceptanceInvalidatedAt?: string
  acceptanceInvalidatedReason?: string
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
}

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

// ---------------------------------------------------------------------------
// 交换包与可恢复导入批次
// ---------------------------------------------------------------------------

/** 交换包允许携带的实体类型：威胁、控制证据、风险（含风险接受） */
export type ExchangeEntityKind = 'threat' | 'evidence' | 'risk'

export type ExchangeEntity =
  | { kind: 'threat'; payload: Threat }
  | { kind: 'evidence'; payload: ControlEvidence }
  | { kind: 'risk'; payload: Risk }

/** 外部评估组送回的交换包 */
export interface ExchangePackage {
  packageId: string
  label: string
  sentBy: string
  sentAt: string
  /** 包导出时所依据的本地修订（revision），用于三方对账 */
  baseRevision: number
  note?: string
  entities: ExchangeEntity[]
  /**
   * 包导出时各实体的基线版本（三向对账的共同祖先）。
   * 本地 == 基线 且包已更新 => 快进；本地 != 基线 => 分叉冲突。
   * 键为 `${kind}:${id}`。
   */
  bases?: Record<string, Threat | ControlEvidence | Risk>
}

/** 对账结果：与包内内容逐条对账后的判定 */
export type ReconcileStatus =
  | 'added' // 本地不存在，直接新增
  | 'unchanged' // 本地与包内一致，无需写入
  | 'fast_forward' // 本地停留在包基线、包已更新，直接采用包内版本
  | 'conflict' // 本地修订与包内修订分叉，保留两版待确认

export type ImportItemStatus =
  | ReconcileStatus
  | 'accepted_local' // 冲突已裁决：保留本地版
  | 'accepted_package' // 冲突已裁决：采用交换包版
  | 'applied' // 已写入本地
  | 'skipped' // 对账后跳过（内容一致）

export interface ImportItem {
  /** 批次内稳定标识，重放幂等键 */
  itemKey: string
  kind: ExchangeEntityKind
  entityId: string
  status: ImportItemStatus
  title: string
  /** 包内版本（冲突时的"交换包版"） */
  packageEntity: Threat | ControlEvidence | Risk
  /** 导入开始时记住的本地修订快照 */
  baseEntity: Threat | ControlEvidence | Risk | null
  /** 冲突时的本地当前版本（"本地版"） */
  localEntity: Threat | ControlEvidence | Risk | null
  resolution?: 'local' | 'package'
  resolvedAt?: string
  resolvedBy?: string
  appliedAt?: string
}

export type BatchPhase =
  | 'reconciling' // 已建批次、对账完成，等待冲突裁决
  | 'applying' // 正在逐项写入（可中断恢复）
  | 'interrupted' // 写入失败，等待从检查点续做
  | 'completed' // 全部完成
  | 'abandoned' // 人工废弃

/** 风险接受失效重算的依据记录 */
export interface AcceptanceBasis {
  id: string
  riskId: string
  riskCode: string
  /** 记录类型：确认接受 / 被变更失效 / 重新确认 */
  type: 'accepted' | 'invalidated' | 'reconfirmed'
  condition: string
  expiresAt?: string
  reason: string
  sourceBatchId?: string
  sourceItemKey?: string
  createdAt: string
  createdBy: string
}

/** 版本差异页与会签中心共同读取的同一批次结论 */
export interface BatchConclusion {
  threatIds: string[]
  threatCount: number
  evidenceCount: number
  riskCount: number
  appliedCount: number
  conflictResolvedCount: number
  invalidatedRiskIds: string[]
  /** 结论生成时引用的批次修订，结论只按批次固化一次 */
  atRevision: number
}

export interface ImportBatch {
  id: string
  packageId: string
  label: string
  sentBy: string
  createdAt: string
  phase: BatchPhase
  baseRevision: number
  items: ImportItem[]
  /** 已成功写入并完整落盘的条目数（完整检查点位置） */
  checkpoint: number
  lastError: string | null
  completedAt: string | null
  /** 批次完成时固化的结论，版本差异与会签中心读取同一份 */
  conclusion: BatchConclusion | null
}

/** 写入失败后的完整检查点：主状态 + 批次位置，恢复时整体装载 */
export interface ImportCheckpoint {
  batchId: string
  savedAt: string
  appliedItemKeys: string[]
  state: ThreatModelState
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  importBatches: ImportBatch[]
  acceptanceHistory: AcceptanceBasis[]
  currentRevision: number
}

export interface ValidationIssue {
  id: string
  kind:
    | 'uncovered_component'
    | 'control_failed'
    | 'risk_acceptance_expired'
    | 'risk_acceptance_invalidated'
    | 'mitigation_conflict'
    | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export interface VersionChange {
  category: string
  id: string
}

export interface VersionDifference {
  added: VersionChange[]
  removed: VersionChange[]
  changed: string[]
}
