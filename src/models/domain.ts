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

export interface RiskAcceptanceRecord {
  id: string
  riskId: string
  status: 'active' | 'invalidated'
  expiresAt: string
  condition: string
  actor: string
  createdAt: string
  /** 接受所依据的威胁/证据内容指纹 */
  basisFingerprint: string
  /** 依据来源：人工会签或交换批次 */
  source: 'manual' | 'import'
  sourceBatchId?: string
  /** 失效原因与时间，历史接受仍保留完整依据 */
  invalidatedAt?: string
  invalidatedReason?: string
  /** 接受时的依据明细：关联威胁、控制与证据快照摘要 */
  basisDetail?: {
    threatSummary: { id: string; code: string; title: string; revision: number }[]
    evidenceSummary: { id: string; title: string; reference: string; valid: boolean; expiresAt: string }[]
  }
  priorRecordId?: string
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
  /** 当前生效接受记录 id；失效后立即清空，历史记录保留在 acceptances 中 */
  activeAcceptanceId?: string
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
  /** 由交换导入批次定稿时，版本与批次结论一一对应 */
  sourceBatchId?: string
  /** 批次对账结论快照，版本差异与会签中心读取同一份结论 */
  batchConclusion?: ImportBatchConclusion
}

export interface ImportBatchConclusion {
  batchId: string
  packageName: string
  reconciledAt: string
  incoming: number
  applied: number
  conflicts: number
  skipped: number
  invalidatedAcceptances: string[]
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
  acceptances: RiskAcceptanceRecord[]
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

/* ============ 外部评估交换包 ============ */

export type ExchangeEntityKind = 'threat' | 'evidence' | 'control' | 'risk_acceptance'

export interface ExchangeThreat {
  /** 外部侧稳定标识，首次导入时确定性映射为本地 id */
  externalId: string
  code: string
  title: string
  category: Threat['category']
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  /** 包内修订号，用于与本地修订对账 */
  revision: number
}

export interface ExchangeEvidence {
  externalId: string
  controlId: string
  title: string
  kind: ControlEvidence['kind']
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface ExchangeRiskAcceptance {
  riskId: string
  expiresAt: string
  condition: string
  actor: string
  createdAt: string
}

export interface ExchangePackage {
  packageId: string
  packageName: string
  sentBy: string
  sentAt: string
  threats: ExchangeThreat[]
  evidence: ExchangeEvidence[]
  controls: SecurityControl[]
  riskAcceptances: ExchangeRiskAcceptance[]
}

/* ============ 可恢复导入批次 ============ */

export type ImportItemStatus =
  | 'pending'
  | 'identical'
  | 'applied'
  | 'conflict'
  | 'resolution_applied'
  | 'skipped'
  | 'failed'

export type ConflictResolution = 'local' | 'incoming'

export interface ImportItem {
  /** 批次内确定性键：类型:稳定 id，重放据此跳过，保证不重复生成 */
  key: string
  kind: ExchangeEntityKind
  /** 外部稳定标识（威胁/证据的 externalId，其余为 id） */
  externalKey: string
  /** 映射到本地集合后的稳定 id */
  localId: string
  label: string
  status: ImportItemStatus
  localRevision: number | null
  incomingRevision: number | null
  conflict: boolean
  conflictFields: string[]
  resolution?: ConflictResolution
  resolutionActor?: string
  resolutionAt?: string
  attempts: number
  lastError?: string
  /** 冲突时保留的两版：本地版与包内版（结构化内容） */
  localVersion?: unknown
  incomingVersion?: unknown
}

export type ImportBatchStatus =
  | 'reconciling'
  | 'awaiting_confirmation'
  | 'applying'
  | 'failed'
  | 'resuming'
  | 'completed'
  | 'discarded'

export interface ImportBatch {
  id: string
  packageId: string
  packageName: string
  sentBy: string
  sentAt: string
  createdAt: string
  updatedAt: string
  status: ImportBatchStatus
  items: ImportItem[]
  /** 导入前完整检查点（深序列化），任何阶段失败都从此恢复后重放 */
  checkpoint: ThreatModelState | null
  /** 对账时刻主数据修订 */
  baseRevision: number
  appliedRevision: number | null
  lastError?: string
  /** 导入定稿生成的版本 id */
  versionId?: string
  conclusion?: ImportBatchConclusion
  /** 因本次内容变化而失效的风险接受记录 id */
  invalidatedAcceptanceIds: string[]
}
