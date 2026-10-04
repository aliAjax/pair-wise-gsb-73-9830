import type { ExchangePackage, ThreatModelState } from '@/models/domain'

/**
 * 构造外部评估组送回的交换包：
 * - thr-01 修订（内容冲突，本地会签需保留两版）
 * - 新增威胁 thr-new-01
 * - ev-03 证据更新（有效期冲突）
 * - 新增证据 ev-new-01
 * - 新增控制 ctl-05
 * - risk-03 重新接受（条件/有效期与本地冲突）
 * - risk-01 首次接受（新增）
 */
export const buildSampleExchangePackage = (state: ThreatModelState): ExchangePackage => {
  const thr01 = state.threats.find((threat) => threat.id === 'thr-01')
  const ev03 = state.evidence.find((item) => item.id === 'ev-03')
  void ev03

  return {
    packageId: `PKG-2026-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    packageName: '外部评估交换包 · 2026Q4 复评',
    sentBy: '外部评估组',
    sentAt: new Date().toISOString(),
    threats: [
      {
        externalId: 'thr-01',
        code: thr01?.code ?? 'TM-001',
        title: '管理网关暴露导致凭证与会话双重滥用',
        category: 'spoofing',
        description:
          '外部复评确认：公网管理入口被枚举后，弱会话与泄露令牌可形成组合攻击，并可横向调用运营高权限接口。',
        severity: 'critical',
        status: 'mitigating',
        componentIds: ['cmp-01', 'cmp-02', 'cmp-06'],
        flowIds: ['flow-01', 'flow-02'],
        externalDependencyIds: [],
        attackPathIds: ['path-01'],
        controlIds: ['ctl-01', 'ctl-05'],
        riskIds: ['risk-01'],
        revision: 3,
      },
      {
        externalId: 'new-threat-signed-sync',
        code: 'TM-101',
        title: '伙伴同步签名密钥被复用导致数据伪造',
        category: 'tampering',
        description:
          '伙伴归因链路签名密钥若与其他环境复用，攻击者可伪造归因数据污染活动结果。',
        severity: 'high',
        status: 'open',
        componentIds: ['cmp-06'],
        flowIds: ['flow-05'],
        externalDependencyIds: ['dep-03'],
        attackPathIds: [],
        controlIds: ['ctl-05'],
        riskIds: ['risk-04'],
        revision: 1,
      },
    ],
    evidence: [
      {
        externalId: 'ev-03',
        controlId: 'ctl-03',
        title: '越权访问扫描报告（外部复评）',
        kind: 'scan',
        reference: 'EXT-SCAN-9012',
        collectedAt: '2026-10-02',
        expiresAt: '2027-01-02',
        owner: '外部评估组',
        valid: true,
      },
      {
        externalId: 'new-ev-signature-attest',
        controlId: 'ctl-05',
        title: '签名密钥隔离配置证明',
        kind: 'attestation',
        reference: 'EXT-ATT-441',
        collectedAt: '2026-10-01',
        expiresAt: '2027-04-01',
        owner: '外部评估组',
        valid: true,
      },
    ],
    controls: [
      {
        id: 'ctl-05',
        name: '伙伴链路独立签名与密钥轮换',
        type: 'preventive',
        status: 'effective',
        owner: '生态集成组',
        componentId: 'cmp-06',
        description: '伙伴同步使用独立签名密钥，按季度轮换并禁用跨环境复用。',
        evidenceIds: ['new-ev-signature-attest'],
      },
    ],
    riskAcceptances: [
      {
        riskId: 'risk-03',
        expiresAt: '2026-12-31',
        condition: '外部复评后接受：继续按日抽检，月结双人审批，并接入异常来源地告警。',
        actor: '外部评估组',
        createdAt: '2026-10-03T09:30:00+08:00',
      },
      {
        riskId: 'risk-01',
        expiresAt: '2026-11-30',
        condition: '管理面白名单收敛完成前，接受残余风险并每日复核登录与会话。',
        actor: '外部评估组',
        createdAt: '2026-10-03T09:35:00+08:00',
      },
    ],
  }
}
