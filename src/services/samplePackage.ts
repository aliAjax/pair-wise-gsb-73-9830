import type { ExchangePackage } from '@/models/domain'
import type { ThreatModelState } from '@/models/domain'

/**
 * 基于当前本地模型构造外部评估组送回的交换包。
 * - thr-01：包内更新（本地未改 => 快进）
 * - ev-04：包内更新证据（本地未改 => 快进；其控制 ctl-04 关联 thr-03/risk-03 => 接受失效）
 * - thr-03：包内更新（本地可能已改 => 冲突两版待确认）
 * - risk-04：包内带回已接受结论（新增接受）
 * - thr-99：本地不存在（新增）
 */
export const buildSamplePackage = (state: ThreatModelState): ExchangePackage => {
  const threat1 = state.threats.find((threat) => threat.id === 'thr-01')
  const threat3 = state.threats.find((threat) => threat.id === 'thr-03')
  const evidence4 = state.evidence.find((evidence) => evidence.id === 'ev-04')
  const risk4 = state.risks.find((risk) => risk.id === 'risk-04')

  const pkg: ExchangePackage = {
    packageId: `pkg-${Date.now().toString(36)}`,
    label: '外部评估组交换包 2026-10',
    sentBy: '外部评估组·陈审',
    sentAt: new Date().toISOString(),
    baseRevision: state.currentRevision,
    note: '返回管理网关复核结论、双人复核证据更新与新增威胁评审。',
    entities: [],
    bases: {},
  }

  if (threat1) {
    const updated: typeof threat1 = structuredClone(threat1)
    updated.title = '管理网关暴露导致凭证滥用（评估组复核版）'
    updated.description =
      '公网管理入口被枚举后，攻击者可能利用弱会话或泄露令牌进入运营服务；评估组补充：夜间无人值守窗口风险窗口更大。'
    updated.severity = 'critical'
    updated.reviewStatus = 'in_review'
    pkg.entities.push({ kind: 'threat', payload: updated })
    pkg.bases!['threat:thr-01'] = structuredClone(threat1)
  }

  if (evidence4) {
    const updated: typeof evidence4 = structuredClone(evidence4)
    updated.title = '导出操作双人复核记录（2026Q4 复评）'
    updated.reference = 'ATT-2026-114'
    updated.collectedAt = '2026-10-02'
    updated.expiresAt = '2027-04-02'
    pkg.entities.push({ kind: 'evidence', payload: updated })
    pkg.bases!['evidence:ev-04'] = structuredClone(evidence4)
  }

  if (threat3) {
    const updated: typeof threat3 = structuredClone(threat3)
    updated.title = '敏感数据批量导出（评估组收敛口径）'
    updated.description =
      '具有报表权限的运营人员可能通过组合筛选获取超出职责范围的数据；评估组要求对月结窗口强制双人审批。'
    updated.severity = 'critical'
    updated.reviewStatus = 'in_review'
    pkg.entities.push({ kind: 'threat', payload: updated })
    pkg.bases!['threat:thr-03'] = structuredClone(threat3)
  }

  if (risk4) {
    const updated: typeof risk4 = structuredClone(risk4)
    updated.status = 'accepted'
    updated.acceptanceExpiresAt = '2026-12-31'
    updated.acceptanceCondition = '伙伴侧签名校验全量上线前接受，异常归因率超过 1% 立即熔断。'
    pkg.entities.push({ kind: 'risk', payload: updated })
    pkg.bases!['risk:risk-04'] = structuredClone(risk4)
  }

  pkg.entities.push({
    kind: 'threat',
    payload: {
      id: 'thr-99',
      code: 'TM-099',
      title: '伙伴归因接口重放攻击',
      category: 'repudiation',
      description: '伙伴同步请求缺少时间戳与 nonce，攻击者截获后可重放归因数据污染模型。',
      severity: 'high',
      status: 'open',
      componentIds: ['cmp-06'],
      flowIds: ['flow-05'],
      externalDependencyIds: ['dep-03'],
      attackPathIds: [],
      controlIds: [],
      riskIds: ['risk-04'],
      reviewStatus: 'draft',
      revision: state.currentRevision,
    },
  })

  return pkg
}

/** 在导入前模拟一条本地修订：让 thr-03 与评估组改动分叉，从而产生冲突两版 */
export const localEditForConflict = (state: ThreatModelState): void => {
  const threat3 = state.threats.find((threat) => threat.id === 'thr-03')
  if (threat3) {
    threat3.title = '敏感数据批量导出（本地会签修订）'
    threat3.description = '本地修订：要求先落地导出水印，再评估批量导出残余风险。'
  }
}
