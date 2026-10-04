<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { Risk } from '@/models/domain'
import { riskLevel, riskScore } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const acceptanceVisible = ref(false)
const selectedRiskId = ref('')
const acceptanceForm = reactive({
  expiresAt: '',
  condition: '',
})

const likelihoods = [5, 4, 3, 2, 1] as const
const impacts = [1, 2, 3, 4, 5] as const

const risksAt = (likelihood: number, impact: number): Risk[] =>
  store.data.risks.filter(
    (risk) => risk.likelihood === likelihood && risk.impact === impact && risk.status !== 'closed',
  )

const selectedRisk = computed(
  () => store.data.risks.find((risk) => risk.id === selectedRiskId.value) ?? null,
)

const openAcceptance = (risk: Risk): void => {
  selectedRiskId.value = risk.id
  acceptanceForm.expiresAt = risk.acceptanceExpiresAt ?? ''
  acceptanceForm.condition = risk.acceptanceCondition ?? ''
  acceptanceVisible.value = true
}

const submitAcceptance = (): void => {
  if (!acceptanceForm.expiresAt || !acceptanceForm.condition.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '到期日与接受条件不能为空', life: 3000 })
    return
  }
  store.acceptRisk(selectedRiskId.value, acceptanceForm.expiresAt, acceptanceForm.condition)
  acceptanceVisible.value = false
  toast.add({ severity: 'success', summary: '风险接受已记录', detail: '已按当前威胁/证据指纹留存依据', life: 2500 })
}

const riskCode = (riskId: string): string =>
  store.data.risks.find((risk) => risk.id === riskId)?.code ?? riskId
const riskTitle = (riskId: string): string =>
  store.data.risks.find((risk) => risk.id === riskId)?.title ?? '（风险已移除）'
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="风险管理"
      title="风险矩阵与接受"
      description="按可能性和影响评估开放风险，检查控制失效与接受过期，并记录接受条件。"
    />

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">5 × 5 风险矩阵</h2>
        <span class="muted">评分 = 可能性 × 影响</span>
      </div>
      <div class="matrix-wrap">
        <div class="matrix-grid">
          <div class="matrix-axis">可能性 \ 影响</div>
          <div v-for="impact in impacts" :key="`head-${impact}`" class="matrix-axis">
            影响 {{ impact }}
          </div>
          <template v-for="likelihood in likelihoods" :key="likelihood">
            <div class="matrix-axis">可能 {{ likelihood }}</div>
            <div
              v-for="impact in impacts"
              :key="`${likelihood}-${impact}`"
              class="matrix-cell"
              :class="`level-${riskLevel(likelihood * impact) === 'critical' ? 5 : riskLevel(likelihood * impact) === 'high' ? 4 : riskLevel(likelihood * impact) === 'medium' ? 3 : 2}`"
            >
              <button
                v-for="risk in risksAt(likelihood, impact)"
                :key="risk.id"
                type="button"
                class="matrix-risk"
                @click="selectedRiskId = risk.id"
              >
                <strong>{{ risk.code }}</strong>
                {{ risk.title }}
              </button>
              <span v-if="risksAt(likelihood, impact).length === 0" class="cell-score">
                {{ likelihood * impact }}
              </span>
            </div>
          </template>
        </div>
      </div>
    </section>

    <div class="risk-layout">
      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">开放风险</h2>
        </div>
        <DataTable :value="store.data.risks.filter((risk) => risk.status !== 'closed')" size="small" stripedRows>
          <Column field="code" header="编号" style="width: 90px" />
          <Column field="title" header="风险" />
          <Column header="评分" style="width: 100px">
            <template #body="{ data }">
              <strong>{{ riskScore(data) }}</strong>
              <StatusTag :value="riskLevel(riskScore(data))" kind="severity" class="risk-tag" />
            </template>
          </Column>
          <Column field="owner" header="负责人" style="width: 135px" />
          <Column header="状态" style="width: 100px">
            <template #body="{ data }">
              <StatusTag :value="data.status" kind="status" />
            </template>
          </Column>
          <Column header="操作" style="width: 180px">
            <template #body="{ data }">
              <Button label="接受" size="small" text @click="openAcceptance(data)" />
              <Button label="关闭" size="small" text @click="store.closeRisk(data.id)" />
            </template>
          </Column>
        </DataTable>
      </section>

      <aside class="validation-panel">
        <h2>风险校验</h2>
        <article
          v-for="issue in store.issues.filter((item) => ['risk_acceptance_expired', 'risk_acceptance_invalidated', 'control_failed', 'missing_evidence'].includes(item.kind))"
          :key="issue.id"
          class="validation-item"
          :class="{ error: issue.severity === 'critical' || issue.severity === 'high' }"
        >
          <i class="validation-dot"></i>
          <div class="validation-copy">
            <strong>{{ issue.title }}</strong>
            <p>{{ issue.detail }}</p>
          </div>
          <StatusTag :value="issue.severity" kind="severity" />
        </article>
      </aside>
    </div>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">风险接受台账（依据随威胁/证据变化自动失效，历史依据保留）</h2>
        <span class="muted">{{ store.data.acceptances.length }} 条记录</span>
      </div>
      <DataTable :value="store.data.acceptances" dataKey="id" size="small" stripedRows>
        <Column header="风险" style="width: 200px">
          <template #body="{ data }">
            <strong>{{ riskCode(data.riskId) }}</strong>
            <div class="muted">{{ riskTitle(data.riskId) }}</div>
          </template>
        </Column>
        <Column header="状态" style="width: 100px">
          <template #body="{ data }">
            <StatusTag :value="data.status === 'active' ? 'active' : 'invalidated'" kind="status" />
          </template>
        </Column>
        <Column field="condition" header="接受条件" />
        <Column field="expiresAt" header="到期日" style="width: 110px" />
        <Column header="依据" style="width: 230px">
          <template #body="{ data }">
            <div class="basis-cell">
              <span>威胁：{{ data.basisDetail?.threatSummary.map((t: any) => t.code).join('、') || '—' }}</span>
              <span>证据：{{ data.basisDetail?.evidenceSummary.length ?? 0 }} 份</span>
              <span class="mono">{{ data.source === 'import' ? '交换批次 ' + data.sourceBatchId?.slice(0, 14) : '人工会签' }}</span>
            </div>
          </template>
        </Column>
        <Column header="失效说明" style="width: 220px">
          <template #body="{ data }">
            <div v-if="data.status === 'invalidated'" class="invalidated-cell">
              <strong>{{ data.invalidatedReason }}</strong>
              <span class="muted">{{ data.invalidatedAt ? new Date(data.invalidatedAt).toLocaleString('zh-CN') : '' }}</span>
            </div>
            <span v-else class="muted">生效中</span>
          </template>
        </Column>
      </DataTable>
    </section>

    <Dialog v-model:visible="acceptanceVisible" header="记录风险接受" modal :style="{ width: '620px' }">
      <div v-if="selectedRisk" class="selected-risk">
        <strong>{{ selectedRisk.code }} · {{ selectedRisk.title }}</strong>
        <span>评分 {{ riskScore(selectedRisk) }} / 25</span>
      </div>
      <div class="acceptance-form">
        <div class="field">
          <label>接受到期日</label>
          <InputText v-model="acceptanceForm.expiresAt" type="date" />
        </div>
        <div class="field">
          <label>接受条件</label>
          <Textarea
            v-model="acceptanceForm.condition"
            rows="4"
            placeholder="说明补偿控制、复核频率和终止条件"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="acceptanceVisible = false" />
        <Button label="确认接受" icon="pi pi-check" @click="submitAcceptance" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.matrix-wrap {
  overflow-x: auto;
  padding: 16px;
}

.matrix-grid {
  min-width: 860px;
}

.matrix-risk {
  width: 100%;
  padding: 5px 7px;
  border: 0;
  border-radius: 4px;
  color: #273247;
  background: #fff;
  font-size: 10px;
  line-height: 1.35;
  text-align: left;
  cursor: pointer;
}

.matrix-risk strong {
  display: block;
  margin-bottom: 2px;
}

.cell-score {
  margin: auto;
  color: #a1a9b6;
  font-size: 10px;
}

.risk-layout {
  display: grid;
  grid-template-columns: minmax(700px, 1.4fr) minmax(320px, 0.6fr);
  gap: 16px;
  align-items: start;
}

.validation-panel {
  display: grid;
  gap: 10px;
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
}

.validation-panel h2 {
  margin: 0 0 2px;
  font-size: 16px;
}

.risk-tag {
  margin-left: 7px;
}

.selected-risk {
  display: flex;
  justify-content: space-between;
  margin-bottom: 18px;
  padding: 12px;
  border: 1px solid #dde2ea;
  border-radius: 5px;
  background: #f8f9fb;
}

.selected-risk span {
  color: #6c7689;
  font-size: 12px;
}

.acceptance-form {
  display: grid;
  gap: 16px;
}

.basis-cell {
  display: grid;
  gap: 3px;
  font-size: 11px;
  color: #5f6a7e;
}

.invalidated-cell {
  display: grid;
  gap: 3px;
  color: #b42318;
  font-size: 11px;
}
</style>
