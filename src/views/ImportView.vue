<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { useRouter } from 'vue-router'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ExchangeEntityKind,
  ExchangePackage,
  ImportBatch,
  ImportItem,
} from '@/models/domain'
import { isWriteFailureArmed } from '@/services/repository'
import { buildSamplePackage, localEditForConflict } from '@/services/samplePackage'
import { kindLabel, pendingConflicts, readyToApply } from '@/services/importBatch'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const router = useRouter()

const packageText = ref('')
const parseError = ref('')
const selectedBatchId = ref('')
const applying = ref(false)
const progress = ref({ done: 0, total: 0 })
const failNextWrite = ref(isWriteFailureArmed())
const syncTimer = window.setInterval(() => {
  failNextWrite.value = isWriteFailureArmed()
}, 600)
onBeforeUnmount(() => window.clearInterval(syncTimer))

const batches = computed(() =>
  [...store.data.importBatches].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)),
)
const selectedBatch = computed(
  () => batches.value.find((batch) => batch.id === selectedBatchId.value) ?? null,
)

const selectBatch = (batch: ImportBatch): void => {
  selectedBatchId.value = batch.id
}

const fillSample = (withLocalEdit: boolean): void => {
  const state = structuredClone(store.data)
  if (withLocalEdit) localEditForConflict(state)
  const pkg = buildSamplePackage(state)
  packageText.value = JSON.stringify(pkg, null, 2)
  parseError.value = ''
  toast.add({
    severity: 'info',
    summary: '已生成样例交换包',
    detail: withLocalEdit
      ? 'thr-03 已模拟本地分叉修订，将产生冲突两版'
      : '包含快进、证据联动、风险接受与新增威胁',
    life: 3200,
  })
}

const parsePackage = (): ExchangePackage | null => {
  parseError.value = ''
  try {
    const parsed = JSON.parse(packageText.value) as ExchangePackage
    if (!parsed.packageId || !Array.isArray(parsed.entities)) {
      throw new Error('缺少 packageId 或 entities 数组')
    }
    const validKinds: ExchangeEntityKind[] = ['threat', 'evidence', 'risk']
    parsed.entities.forEach((entry, index) => {
      if (!entry.kind || !validKinds.includes(entry.kind) || !entry.payload?.id) {
        throw new Error(`第 ${index + 1} 条实体格式不合法`)
      }
    })
    return parsed
  } catch (error) {
    parseError.value = error instanceof Error ? error.message : 'JSON 解析失败'
    return null
  }
}

const createFromText = (): void => {
  const pkg = parsePackage()
  if (!pkg) {
    toast.add({ severity: 'error', summary: '交换包解析失败', detail: parseError.value, life: 3500 })
    return
  }
  const batch = store.openImportBatch(pkg)
  selectedBatchId.value = batch.id
  const conflicts = pendingConflicts(batch).length
  toast.add({
    severity: conflicts ? 'warn' : 'success',
    summary: '对账完成',
    detail: `共 ${batch.items.length} 条，${conflicts} 条冲突保留两版待确认`,
    life: 3500,
  })
}

const onFile = async (event: Event): Promise<void> => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  packageText.value = await file.text()
  input.value = ''
  toast.add({ severity: 'info', summary: '已读入交换包文件', detail: file.name, life: 2200 })
}

const resolve = (itemKey: string, resolution: 'local' | 'package'): void => {
  if (!selectedBatch.value) return
  store.resolveImportItem(selectedBatch.value.id, itemKey, resolution)
  toast.add({
    severity: 'success',
    summary: '冲突已裁决',
    detail: resolution === 'local' ? '已选择保留本地版' : '已选择采用交换包版',
    life: 2200,
  })
}

const abandon = (): void => {
  if (!selectedBatch.value) return
  store.abandonBatch(selectedBatch.value.id)
  toast.add({ severity: 'info', summary: '批次已废弃', detail: '未写入任何内容', life: 2500 })
}

const runApply = async (): Promise<void> => {
  if (!selectedBatch.value) return
  applying.value = true
  progress.value = { done: 0, total: selectedBatch.value.items.length }
  const result = await store.applyImportBatch(selectedBatch.value.id, (event) => {
    progress.value = event
  })
  applying.value = false
  if (result.ok) {
    toast.add({
      severity: 'success',
      summary: '导入批次已完成',
      detail: '结论已固化，版本差异与会签中心读取同一批次结论',
      life: 3800,
    })
  } else {
    toast.add({
      severity: 'error',
      summary: '写入中断，已保留完整检查点',
      detail: result.error,
      life: 5000,
    })
  }
}

const resume = async (): Promise<void> => {
  if (!recoveryBatch.value) return
  selectedBatchId.value = recoveryBatch.value.id
  await runApply()
}

const recoveryBatch = computed(
  () => batches.value.find((batch) => batch.id === store.recoveryNotice?.batchId) ?? null,
)

const phaseLabel = (phase: ImportBatch['phase']): string =>
  ({
    reconciling: '对账完成待确认',
    applying: '写入中',
    interrupted: '写入中断可恢复',
    completed: '已完成',
    abandoned: '已废弃',
  })[phase]

const statusLabel = (status: ImportItem['status']): string =>
  ({
    added: '新增',
    unchanged: '一致',
    fast_forward: '快进更新',
    conflict: '冲突待确认',
    accepted_local: '保留本地版',
    accepted_package: '采用交换包',
    applied: '已写入',
    skipped: '已跳过',
  })[status]

const fieldRows = (item: ImportItem): { field: string; local: string; pkg: string }[] => {
  const local = item.localEntity as unknown as Record<string, unknown> | null
  const pkg = item.packageEntity as unknown as Record<string, unknown>
  const fields =
    item.kind === 'threat'
      ? ['title', 'description', 'severity', 'status', 'reviewStatus']
      : item.kind === 'evidence'
        ? ['title', 'reference', 'collectedAt', 'expiresAt', 'valid', 'owner']
        : ['title', 'likelihood', 'impact', 'status', 'acceptanceExpiresAt', 'acceptanceCondition']
  return fields.map((field) => ({
    field,
    local: local === null ? '（本地不存在）' : String(local[field] ?? '—'),
    pkg: String(pkg[field] ?? '—'),
  }))
}

const fieldLabel = (field: string): string =>
  ({
    title: '标题',
    description: '描述',
    severity: '严重度',
    status: '状态',
    reviewStatus: '会签状态',
    reference: '引用编号',
    collectedAt: '采集日',
    expiresAt: '到期日',
    valid: '有效',
    owner: '责任人',
    likelihood: '可能性',
    impact: '影响',
    acceptanceExpiresAt: '接受到期',
    acceptanceCondition: '接受条件',
  })[field] ?? field

const conflictItems = computed(() =>
  selectedBatch.value ? pendingConflicts(selectedBatch.value) : [],
)
const batchReady = computed(() =>
  selectedBatch.value ? readyToApply(selectedBatch.value) : false,
)
const isActive = (batch: ImportBatch): boolean =>
  batch.phase === 'reconciling' || batch.phase === 'applying' || batch.phase === 'interrupted'
const writableCount = (batch: ImportBatch): number =>
  batch.items.filter((item) => item.status !== 'unchanged').length
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="外部评估组交换"
      title="交换包可恢复导入"
      description="记住本地修订并与包内三方对账：新增快进自动采用，本地分叉冲突保留两版待确认；写入失败从完整检查点续做，重放不重复生成。"
    />

    <section v-if="store.recoveryNotice" class="recovery-banner">
      <div class="recovery-copy">
        <strong><i class="pi pi-history"></i> 检测到上次导入写入中断</strong>
        <p>
          批次「{{ store.recoveryNotice.label }}」已从完整检查点恢复：
          已完成 {{ store.recoveryNotice.appliedCount }}/{{ store.recoveryNotice.totalCount }} 条，
          检查点保存于 {{ new Date(store.recoveryNotice.savedAt).toLocaleString('zh-CN') }}。
          续做不会重复写入已完成条目。
        </p>
      </div>
      <div class="recovery-actions">
        <Button label="从检查点续做" icon="pi pi-play" :loading="applying" @click="resume" />
        <Button
          label="稍后处理"
          severity="secondary"
          outlined
          @click="store.dismissRecoveryNotice()"
        />
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">1. 读入交换包</h2>
        <div class="action-stack">
          <Button label="生成样例包" icon="pi pi-file" severity="secondary" outlined @click="fillSample(false)" />
          <Button
            label="生成分叉样例包"
            icon="pi pi-clone"
            severity="secondary"
            outlined
            @click="fillSample(true)"
          />
          <label class="file-button">
            <input type="file" accept="application/json,.json" @change="onFile" />
            <Button label="选择文件" icon="pi pi-upload" severity="secondary" outlined />
          </label>
        </div>
      </div>
      <div class="package-input">
        <Textarea
          v-model="packageText"
          rows="9"
          placeholder='粘贴交换包 JSON：{ packageId, label, sentBy, baseRevision, entities: [...], bases: {...} }'
        />
        <div class="package-foot">
          <label class="fail-switch">
            <ToggleSwitch
              :model-value="failNextWrite"
              @update:model-value="(value) => { if (value) { failNextWrite = true; store.armWriteFailure() } else { failNextWrite = false } }"
            />
            <span>模拟下一次本地写入失败（验证检查点恢复）</span>
          </label>
          <Button label="建批次并对账" icon="pi pi-check-double" @click="createFromText" />
        </div>
        <p v-if="parseError" class="parse-error"><i class="pi pi-exclamation-circle"></i> {{ parseError }}</p>
      </div>
    </section>

    <div v-if="selectedBatch" class="batch-workspace">
      <section class="panel batch-panel">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">2. 批次对账与裁决</h2>
            <span class="muted">{{ selectedBatch.label }} · {{ selectedBatch.sentBy }}</span>
          </div>
          <StatusTag :value="phaseLabel(selectedBatch.phase)" kind="review" />
        </div>

        <div v-if="selectedBatch.lastError" class="batch-error">
          <i class="pi pi-exclamation-triangle"></i>
          <span>{{ selectedBatch.lastError }}</span>
        </div>

        <div class="batch-metrics">
          <div><span>条目</span><strong>{{ selectedBatch.items.length }}</strong></div>
          <div><span>待写入</span><strong>{{ writableCount(selectedBatch) }}</strong></div>
          <div><span>冲突待确认</span><strong class="danger-text">{{ conflictItems.length }}</strong></div>
          <div>
            <span>检查点</span>
            <strong>{{ selectedBatch.checkpoint }}/{{ selectedBatch.items.length }}</strong>
          </div>
        </div>

        <div v-if="applying" class="apply-progress">
          <ProgressBar
            :value="progress.total ? Math.round((progress.done / progress.total) * 100) : 0"
          />
          <span>{{ progress.done }}/{{ progress.total }} 已落盘</span>
        </div>

        <div class="item-list">
          <article
            v-for="item in selectedBatch.items"
            :key="item.itemKey"
            class="item-card"
            :class="{ conflict: item.status === 'conflict' }"
          >
            <header>
              <div>
                <span class="mono">{{ kindLabel(item.kind) }} · {{ item.entityId }}</span>
                <h3>{{ item.title }}</h3>
              </div>
              <StatusTag :value="statusLabel(item.status)" kind="status" />
            </header>

            <div v-if="item.status === 'conflict'" class="conflict-body">
              <p class="conflict-note">
                本地已相对包基线修订，包内也更新了同一实体，两版均已保留，请裁决：
              </p>
              <div class="two-versions">
                <div class="version-col local-col">
                  <h4><i class="pi pi-home"></i> 本地版</h4>
                  <dl>
                    <template v-for="row in fieldRows(item)" :key="row.field">
                      <dt>{{ fieldLabel(row.field) }}</dt>
                      <dd :class="{ diff: row.local !== row.pkg }">{{ row.local }}</dd>
                    </template>
                  </dl>
                </div>
                <div class="version-col pkg-col">
                  <h4><i class="pi pi-send"></i> 交换包版</h4>
                  <dl>
                    <template v-for="row in fieldRows(item)" :key="row.field">
                      <dt>{{ fieldLabel(row.field) }}</dt>
                      <dd :class="{ diff: row.local !== row.pkg }">{{ row.pkg }}</dd>
                    </template>
                  </dl>
                </div>
              </div>
              <div class="resolve-actions">
                <Button
                  label="保留本地版"
                  icon="pi pi-home"
                  severity="secondary"
                  outlined
                  @click="resolve(item.itemKey, 'local')"
                />
                <Button
                  label="采用交换包版"
                  icon="pi pi-send"
                  @click="resolve(item.itemKey, 'package')"
                />
              </div>
            </div>

            <div v-else-if="item.resolution" class="resolution-note">
              <i class="pi pi-check-circle"></i>
              已裁决：{{ item.resolution === 'local' ? '保留本地版（包版本留档）' : '采用交换包版（本地版留档）' }}
              <span class="muted">· {{ item.resolvedBy }} · {{ new Date(item.resolvedAt ?? '').toLocaleString('zh-CN') }}</span>
            </div>
          </article>
        </div>

        <div class="batch-footer">
          <Button
            v-if="selectedBatch.phase !== 'completed' && selectedBatch.phase !== 'abandoned'"
            label="废弃批次"
            severity="secondary"
            outlined
            :disabled="applying"
            @click="abandon"
          />
          <div class="action-stack">
            <Button
              v-if="selectedBatch.phase === 'interrupted'"
              label="从检查点续做"
              icon="pi pi-play"
              :loading="applying"
              @click="runApply"
            />
            <Button
              v-else-if="selectedBatch.phase === 'reconciling'"
              label="开始写入批次"
              icon="pi pi-database"
              :disabled="!batchReady || applying"
              @click="runApply"
            />
            <small v-if="!batchReady && selectedBatch.phase === 'reconciling'" class="muted">
              仍有 {{ conflictItems.length }} 条冲突需要裁决
            </small>
          </div>
        </div>
      </section>

      <aside class="batch-side">
        <section v-if="selectedBatch.conclusion" class="panel conclusion-panel">
          <div class="panel-header"><h2 class="panel-title">批次结论（唯一口径）</h2></div>
          <dl class="conclusion-grid">
            <dt>写入条目</dt><dd>{{ selectedBatch.conclusion.appliedCount }}</dd>
            <dt>威胁</dt><dd>{{ selectedBatch.conclusion.threatCount }}</dd>
            <dt>证据</dt><dd>{{ selectedBatch.conclusion.evidenceCount }}</dd>
            <dt>风险接受</dt><dd>{{ selectedBatch.conclusion.riskCount }}</dd>
            <dt>冲突裁决</dt><dd>{{ selectedBatch.conclusion.conflictResolvedCount }}</dd>
            <dt>接受失效重算</dt>
            <dd class="danger-text">{{ selectedBatch.conclusion.invalidatedRiskIds.length }}</dd>
          </dl>
          <p class="muted">版本差异页与会签中心读取本结论。</p>
          <div class="conclusion-links">
            <Button label="前往会签中心" size="small" text @click="router.push('/reviews')" />
            <Button label="前往版本差异" size="small" text @click="router.push('/versions')" />
            <Button label="查看风险矩阵" size="small" text @click="router.push('/risks')" />
          </div>
        </section>

        <section class="panel history-panel">
          <div class="panel-header">
            <h2 class="panel-title">批次历史</h2>
            <span class="muted">{{ batches.length }}</span>
          </div>
          <div class="batch-history">
            <button
              v-for="batch in batches"
              :key="batch.id"
              type="button"
              class="history-item"
              :class="{ active: batch.id === selectedBatchId }"
              @click="selectBatch(batch)"
            >
              <div>
                <strong>{{ batch.label }}</strong>
                <span>{{ batch.sentBy }} · {{ new Date(batch.createdAt).toLocaleString('zh-CN') }}</span>
              </div>
              <StatusTag
                :value="phaseLabel(batch.phase)"
                :kind="isActive(batch) ? 'review' : 'status'"
              />
            </button>
            <div v-if="batches.length === 0" class="empty-state">尚未建立导入批次。</div>
          </div>
        </section>
      </aside>
    </div>
  </div>
</template>

<style scoped>
.recovery-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 14px 18px;
  border: 1px solid #e0b341;
  border-radius: 7px;
  background: #fff8e6;
}

.recovery-copy {
  display: grid;
  gap: 5px;
}

.recovery-copy strong {
  font-size: 14px;
}

.recovery-copy p {
  margin: 0;
  color: #6c623f;
  font-size: 12px;
  line-height: 1.6;
}

.recovery-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.package-input {
  display: grid;
  gap: 12px;
  padding: 16px;
}

.package-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}

.fail-switch {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: #7a5a12;
  font-size: 12px;
}

.file-button input {
  display: none;
}

.parse-error {
  margin: 0;
  color: #b42318;
  font-size: 12px;
}

.batch-workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.55fr) minmax(300px, 0.45fr);
  gap: 16px;
  align-items: start;
}

.batch-side {
  display: grid;
  gap: 16px;
}

.batch-error {
  display: flex;
  gap: 9px;
  margin: 14px 16px 0;
  padding: 10px 12px;
  border-radius: 5px;
  color: #8a2b18;
  background: #fdecea;
  font-size: 12px;
}

.batch-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1px;
  margin: 16px;
  overflow: hidden;
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  background: #e2e6ec;
}

.batch-metrics > div {
  display: grid;
  gap: 5px;
  padding: 11px 13px;
  background: #fafbfc;
}

.batch-metrics span {
  color: #717c90;
  font-size: 11px;
}

.batch-metrics strong {
  font-size: 19px;
}

.apply-progress {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 110px;
  align-items: center;
  gap: 12px;
  margin: 0 16px 12px;
  color: #647087;
  font-size: 12px;
}

.item-list {
  display: grid;
  gap: 12px;
  padding: 0 16px 16px;
}

.item-card {
  border: 1px solid #e1e5eb;
  border-radius: 6px;
  background: #fff;
}

.item-card.conflict {
  border-color: #e0a295;
  box-shadow: 0 0 0 1px rgba(196, 50, 10, 0.08);
}

.item-card > header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
}

.item-card h3 {
  margin: 5px 0 0;
  font-size: 14px;
}

.conflict-body {
  padding: 0 14px 14px;
  border-top: 1px dashed #e3d2cd;
}

.conflict-note {
  margin: 10px 0;
  color: #8a4a3c;
  font-size: 12px;
}

.two-versions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.version-col {
  padding: 11px 12px;
  border-radius: 6px;
}

.version-col h4 {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0 0 8px;
  font-size: 12px;
}

.local-col {
  border: 1px solid #d7dde6;
  background: #f6f8fb;
}

.pkg-col {
  border: 1px solid #cfe3d8;
  background: #f1faf5;
}

.version-col dl {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr);
  gap: 5px 9px;
  margin: 0;
}

.version-col dt {
  color: #7a8496;
  font-size: 11px;
}

.version-col dd {
  margin: 0;
  color: #3b465a;
  font-size: 11px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}

.version-col dd.diff {
  font-weight: 600;
  color: #8a2b18;
}

.resolve-actions {
  display: flex;
  justify-content: flex-end;
  gap: 9px;
  margin-top: 11px;
}

.resolution-note {
  padding: 0 14px 12px;
  color: #2f6e52;
  font-size: 12px;
}

.batch-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px 16px;
}

.conclusion-panel dl {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px 14px;
  margin: 0;
  padding: 14px 16px;
}

.conclusion-panel dt {
  color: #6f7a8d;
  font-size: 12px;
}

.conclusion-panel dd {
  margin: 0;
  font-weight: 650;
}

.conclusion-panel p {
  margin: 0;
  padding: 0 16px 8px;
  font-size: 11px;
}

.conclusion-links {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  padding: 0 8px 10px;
}

.batch-history {
  display: grid;
  gap: 6px;
  max-height: 420px;
  padding: 12px 14px;
  overflow-y: auto;
}

.history-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px;
  border: 1px solid #e3e7ed;
  border-radius: 6px;
  background: #fff;
  text-align: left;
  cursor: pointer;
}

.history-item.active {
  border-color: #7898bb;
  background: #f4f8fd;
}

.history-item strong {
  display: block;
  font-size: 12px;
}

.history-item span {
  display: block;
  margin-top: 3px;
  color: #8590a2;
  font-size: 10px;
}
</style>
