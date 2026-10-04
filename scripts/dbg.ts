import { createSeedState } from '@/models/seed'
import { createBatch } from '@/services/importBatches'
const state = createSeedState()
const batch = createBatch(state, {
  packageId: 'P1', packageName: 'n', sentBy: 'x', sentAt: 't',
  threats: [{ externalId: 'thr-01', code: 'TM-001', title: 'X', category: 'spoofing', description: 'd', severity: 'critical', status: 'mitigating', componentIds: ['cmp-01'], flowIds: [], externalDependencyIds: [], attackPathIds: [], controlIds: ['ctl-01'], riskIds: ['risk-01'], revision: 3 }],
  evidence: [{ externalId: 'ev-03', controlId: 'ctl-03', title: 'X', kind: 'scan', reference: 'R', collectedAt: '2026-10-02', expiresAt: '2027-01-02', owner: 'o', valid: true }],
  controls: [],
  riskAcceptances: [{ riskId: 'risk-03', expiresAt: '2026-12-31', condition: 'c2', actor: 'a', createdAt: 't' }],
})
console.log(JSON.stringify(batch.items.map((i) => ({ key: i.key, conflict: i.conflict, fields: i.conflictFields, lr: i.localRevision, ir: i.incomingRevision })), null, 2))
