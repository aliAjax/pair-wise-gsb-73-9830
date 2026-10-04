import { createSeedState } from '@/models/seed'
import { advanceBatch, createBatch, resolveConflict } from '@/services/importBatches'
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v))
const state = createSeedState()
const holder: any = { state: null, batch: null }
const commit = (s: any, b: any) => { holder.state = clone(s); holder.batch = clone(b) }
const p = {
  packageId: 'P1', packageName: 'n', sentBy: 'x', sentAt: 't',
  threats: [{ externalId: 'thr-01', code: 'TM-001', title: 'X', category: 'spoofing' as const, description: 'd', severity: 'critical' as const, status: 'mitigating' as const, componentIds: ['cmp-01'], flowIds: [], externalDependencyIds: [], attackPathIds: [], controlIds: ['ctl-01'], riskIds: ['risk-01'], revision: 3 }],
  evidence: [{ externalId: 'ev-03', controlId: 'ctl-03', title: 'X', kind: 'scan' as const, reference: 'R', collectedAt: '2026-10-02', expiresAt: '2027-01-02', owner: 'o', valid: true }],
  controls: [],
  riskAcceptances: [{ riskId: 'risk-03', expiresAt: '2026-12-31', condition: 'c2', actor: 'a', createdAt: 't' }],
}
const batch = createBatch(state, p)
const o1 = advanceBatch(state, batch, commit)
console.log('after advance:', o1.awaitingConfirmation, batch.status)
const o2 = resolveConflict(holder.state, batch, 'threat:thr-01', 'incoming', 't', commit)
console.log('after resolve:', o2.awaitingConfirmation, batch.status)
console.log(batch.items.map((i: any) => ({ key: i.key, st: i.status, res: i.resolution })))
