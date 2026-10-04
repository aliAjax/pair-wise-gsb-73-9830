<script setup lang="ts">
import { computed } from 'vue'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import type { ExchangePackage, ImportItem } from '@/models/domain'
import { buildSampleExchangePackage } from '@/services/exchangePackage'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()

const statusMeta: Record<string, { label: string; severity: string }> = {
  reconciling: { label: '对账中', severity: 'info' },
  awaiting_confirmation: { label: '待确认冲突', severity: 'warn' },
  applying: { label: '写入中', severity: 'info' },
  failed: { label: '写入失败', severity: 'danger' },
  resuming: { label: '从检查点恢复', severity: 'info' },
  completed: { label: '已完成', severity: 'success' },
  discarded: { label: '已放弃', severity: 'secondary' },
}

const itemStatusMeta: Record<string, { label: string; severity: string }> = {
  pending: { label: '待写入', severity: 'secondary' },
  identical: { label: '内容一致·跳过', severity: 'success' },
  applied: { label: '已写入', severity: 'success' },
  conflict: { label: '冲突·两版待确认', severity: 'warn' },
  resolution_applied: { label: '已按确认写入', severity: 'success' },
  skipped: { label: '跳过', severity: 'secondary' },
  failed: { label: '写入失败', severity: 'danger' },
}

const kindLabel: Record<string, string> = {
  threat: '威胁',
  evidence: '控制证据',
  control: '控制',
  risk_acceptance: '风险接受',
}

const fieldLabel: Record<string, string> = {
  revision: '修订号',
  title: '标题',
  description: '描述',
  severity: '严重级别',
  status: '状态',
  componentIds: '关联组件',
  flowIds: '关联数据流',
  controlIds: '关联控制',
  riskIds: '关联风险',
  expiresAt: '有效期',
  condition: '接受条件',
  reference: '引用编号',
  valid: '有效性',
  owner: '负责人',
  controlId: '关联控制',
  name: '名称',
  basisFingerprint: '依据指纹',
}

const activeBatch = computed(() => store.activeBatch)
const historyBatches = computed(() =>
  store.batches.filter(
    (batch) => ['completed', 'discarded'].includes(batch.status) && batch.id !== activeBatch.value?.id,
  ),
)

const progress = computed(() => {
  const batch = activeBatch.value
  if (!batch) return 0
  const done = batch.items.filter((item) =>
    ['applied', 'identical', 'resolution_applied', 'skipped'].includes(item.status),
  ).length
  return Math.round((done / batch.items.length) * 100)
})

const fieldNames = (fields: string[]): string =>
  fields.map((field) => fieldLabel[field] ?? field).join('、') || '内容差异'

const formatValue = (item: ImportItem, version: 'local' | 'incoming'): string => {
  const value = version === 'local' ? item.localVersion : item.incomingVersion
  if (value === null || value === undefined) return '（无）'
  return JSON.stringify(value, null, 2)
}

const versionTitle = (item: ImportItem, version: 'local' | 'incoming'): string => {
  if (version === 'local') return `本地版本${item.localRevision !== null ? `（r${item.localRevision}）` : ''}`
  return `包内版本${item.incomingRevision !== null ? `（r${item.incomingRevision}）` : ''}`
}

const importPackage = (pkg: ExchangePackage): void => {
  if (store.hasActiveBatch) {
    toast.add({
      severity: 'warn',
      summary: '存在未完成批次',
      detail: '请先完成冲突确认或放弃当前批次，再导入新交换包。',
      life: 3500,
    })
    return
  }
  store.startImport(pkg)
  if (store.lastWriteError) {
    toast.add({
      severity: 'error',
      summary: '写入失败',
      detail: `${store.lastWriteError}；批次检查点已保存，可从检查点续做。`,
      life: 4500,
    })
  } else {
    toast.add({
      severity: 'success',
      summary: '交换包已建批次并对账',
      detail: '无冲突条目已幂等写入，冲突条目保留两版待确认。',
      life: 3500,
    })
  }
}

const importSample = (): void => importPackage(buildSampleExchangePackage(store.data))

const parsePackageFile = async (file: File): Promise<void> => {
  try {
    const text = await file.text()
    const parsed = JSON.parse(text) as Partial<ExchangePackage>
    if (!parsed.packageId || !Array.isArray(parsed.threats) || !Array.isArray(parsed.evidence)) {
      throw new Error('缺少 packageId / threats / evidence 字段')
    }
    importPackage({
      packageId: parsed.packageId,
      packageName: parsed.packageName ?? '外部交换包',
      sentBy: parsed.sentBy ?? '外部评估组',
      sentAt: parsed.sentAt ?? new Date().toISOString(),
      threats: parsed.threats,
      evidence: parsed.evidence,
      controls: parsed.controls ?? [],
      riskAcceptances: parsed.riskAcceptances ?? [],
    })
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: '交换包解析失败',
      detail: error instanceof Error ? error.message : String(error),
      life: 4000,
    })
  }
}

const onFileChange = (event: Event): void => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) void parsePackageFile(file)
  input.value = ''
}

const resolve = (item: ImportItem, resolution: 'local' | 'incoming'): void => {
  store.resolveImportConflict(item.key, resolution)
  if (store.lastWriteError) {
    toast.add({
      severity: 'error',
      summary: '确认写入失败',
      detail: `${store.lastWriteError}；结论已保留，可从检查点续做。`,
      life: 4500,
    })
  } else if (!store.hasActiveBatch) {
    toast.add({
      severity: 'success',
      summary: '批次已定稿',
      detail: '版本快照、会签范围与风险接受已按同一批次结论更新。',
      life: 3500,
    })
  } else {
    toast.add({ severity: 'success', summary: '冲突已确认', detail: '该条目结论已写入，其余冲突继续确认。', life: 2500 })
  }
}

const resume = (): void => {
  store.resumeImport()
  if (store.lastWriteError) {
    toast.add({
      severity: 'error',
      summary: '恢复仍失败',
      detail: `${store.lastWriteError}；主数据保持检查点状态，可稍后重试。`,
      life: 4500,
    })
  } else {
    toast.add({
      severity: 'success',
      summary: '已从检查点续做',
      detail: '已确认结论幂等重放，未重复生成记录。',
      life: 3200,
    })
  }
}

const discard = (): void => {
  store.discardImport()
  toast.add({ severity: 'secondary', summary: '批次已放弃', detail: '主数据已恢复到导入前检查点。', life: 3000 })
}

const armFailureAndApply = (): void => {
  // 先让下一次写入失败：用于演示“写入失败 → 从检查点续做”
  store.armWriteFailure()
  toast.add({
    severity: 'warn',
    summary: '已注入下一次写入故障',
    detail: '点击任一冲突的确认按钮即可观察失败与恢复。',
    life: 3000,
  })
}

const armFailureThenResume = (): void => {
  store.armWriteFailure()
  resume()
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="外部评估交换"
      title="交换包可恢复导入"
      description="导入即建批次并保存完整检查点；与本地修订对账，冲突保留本地版与包内版两版逐条确认。写入失败可从检查点续做，刷新或重开页面自动继续，重放不重复生成。"
    />

    <section class="panel import-entry">
      <div class="entry-copy">
        <h2 class="panel-title">外部评估组交换包</h2>
        <p class="muted">
          批次只增量写入威胁、控制证据、控制与风险接受，不再整包覆盖本地会签；
          威胁或证据变化时，关联风险接受立即失效并按新依据重算，已确认结果保留依据。
        </p>
      </div>
      <div class="entry-actions">
        <Button label="载入示例交换包" icon="pi pi-download" @click="importSample" />
        <label class="file-button">
          <Button label="选择交换包 JSON" icon="pi pi-upload" severity="secondary" outlined type="button" />
          <input type="file" accept="application/json,.json" @change="onFileChange" hidden />
        </label>
        <Button
          v-if="activeBatch"
          label="从检查点续做"
          icon="pi pi-replay"
          severity="warning"
          outlined
          :disabled="activeBatch.status === 'awaiting_confirmation'"
          @click="resume"
        />
        <Button
          v-if="activeBatch"
          label="注入一次写入故障"
          icon="pi pi-bolt"
          severity="danger"
          text
          @click="armFailureAndApply"
        />
      </div>
    </section>

    <section v-if="activeBatch" class="panel batch-panel">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">{{ activeBatch.packageName }}</h2>
          <span class="muted mono">{{ activeBatch.id }} · 包号 {{ activeBatch.packageId }} · 来自 {{ activeBatch.sentBy }}</span>
        </div>
        <Tag :value="statusMeta[activeBatch.status]?.label ?? activeBatch.status" :severity="statusMeta[activeBatch.status]?.severity as any" />
      </div>

      <div class="batch-progress">
        <ProgressBar :value="progress" style="height: 8px" />
        <div class="progress-meta">
          <span>基线 r{{ activeBatch.baseRevision }} → 目标 {{ activeBatch.appliedRevision ? `r${activeBatch.appliedRevision}` : '待定稿' }}</span>
          <span>{{ progress }}% · {{ activeBatch.items.length }} 个条目</span>
        </div>
      </div>

      <div v-if="activeBatch.lastError" class="error-banner">
        <i class="pi pi-exclamation-triangle"></i>
        <div>
          <strong>最近一次写入失败：</strong>{{ activeBatch.lastError }}
          <span>主数据未被破坏，已保留检查点。点击“从检查点续做”可重放已确认结论。</span>
        </div>
        <Button label="立即续做" icon="pi pi-replay" size="small" severity="warning" @click="resume" />
      </div>

      <div class="batch-items">
        <article v-for="item in activeBatch.items" :key="item.key" class="batch-item" :class="{ conflict: item.status === 'conflict' }">
          <div class="item-head">
            <div>
              <Tag :value="kindLabel[item.kind] ?? item.kind" severity="secondary" style="margin-right: 8px" />
              <strong>{{ item.label }}</strong>
            </div>
            <Tag :value="itemStatusMeta[item.status]?.label ?? item.status" :severity="itemStatusMeta[item.status]?.severity as any" />
          </div>
          <div v-if="item.status === 'conflict'" class="conflict-body">
            <p class="conflict-fields">冲突字段：{{ fieldNames(item.conflictFields) }}</p>
            <div class="version-grid">
              <div class="version-card local">
                <header>{{ versionTitle(item, 'local') }}</header>
                <pre>{{ formatValue(item, 'local') }}</pre>
                <Button
                  label="保留本地版"
                  icon="pi pi-save"
                  size="small"
                  severity="secondary"
                  outlined
                  @click="resolve(item, 'local')"
                />
              </div>
              <div class="version-card incoming">
                <header>{{ versionTitle(item, 'incoming') }}</header>
                <pre>{{ formatValue(item, 'incoming') }}</pre>
                <Button label="采用包内版" icon="pi pi-check" size="small" @click="resolve(item, 'incoming')" />
              </div>
            </div>
            <p v-if="item.kind === 'risk_acceptance'" class="muted hint">
              关联威胁或证据已在本批次中变化：确认接受前，旧接受已按新依据失效重算；确认结果会保留新老两版接受依据。
            </p>
          </div>
          <div v-else class="item-foot">
            <span v-if="item.resolution" class="muted">
              确认结论：{{ item.resolution === 'local' ? '保留本地版' : '采用包内版' }} · {{ item.resolutionActor }} · {{ item.resolutionAt ? new Date(item.resolutionAt).toLocaleString('zh-CN') : '' }}
            </span>
            <span v-else-if="item.kind === 'risk_acceptance' && item.status === 'pending'" class="muted">等待威胁/证据写入后按新依据重算。</span>
            <span v-else class="muted">
              <template v-if="item.localRevision !== null">本地 r{{ item.localRevision }} → 包内 r{{ item.incomingRevision }}</template>
            </span>
            <span v-if="item.attempts > 0" class="muted">尝试 {{ item.attempts }} 次</span>
          </div>
        </article>
      </div>

      <div class="batch-footer">
        <div class="invalidation-note">
          <i class="pi pi-shield"></i>
          <span>
            本批次已使 <strong>{{ activeBatch.invalidatedAcceptanceIds.length }}</strong> 条风险接受按依据变化失效重算；
            历史接受与依据在风险矩阵中可查。
          </span>
        </div>
        <div class="footer-actions">
          <Button
            v-if="activeBatch.status === 'failed'"
            label="从检查点续做"
            icon="pi pi-replay"
            severity="warning"
            @click="resume"
          />
          <Button
            v-if="activeBatch.status === 'failed'"
            label="模拟再次失败后续做"
            icon="pi pi-bolt"
            severity="danger"
            text
            @click="armFailureThenResume"
          />
          <Button label="放弃批次并恢复检查点" icon="pi pi-times" severity="secondary" text @click="discard" />
        </div>
      </div>
    </section>

    <section v-else-if="historyBatches.length === 0" class="panel empty-panel">
      <div class="empty-state">
        尚无导入批次。载入示例交换包可看到：修订对账、冲突双版、检查点恢复与风险接受联动。
      </div>
    </section>

    <section v-if="historyBatches.length" class="panel">
      <div class="panel-header">
        <h2 class="panel-title">批次历史（版本差异与会签中心读取同一结论）</h2>
      </div>
      <div class="history-list">
        <article v-for="batch in historyBatches" :key="batch.id" class="history-item">
          <div>
            <strong>{{ batch.packageName }}</strong>
            <span class="muted mono">{{ batch.id }}</span>
          </div>
          <div class="history-stats">
            <Tag :value="statusMeta[batch.status]?.label ?? batch.status" :severity="statusMeta[batch.status]?.severity as any" />
            <span v-if="batch.conclusion" class="muted">
              写入 {{ batch.conclusion.applied }} · 冲突确认 {{ batch.conclusion.conflicts }} · 一致跳过 {{ batch.conclusion.skipped }} · 失效接受 {{ batch.conclusion.invalidatedAcceptances.length }}
            </span>
            <span v-if="batch.versionId" class="muted">定稿版本 r{{ batch.appliedRevision }}</span>
          </div>
        </article>
      </div>
    </section>
  </div>
</template>

<style scoped>
.import-entry {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 18px 20px;
}

.entry-copy {
  display: grid;
  gap: 8px;
  max-width: 720px;
}

.entry-copy p {
  margin: 0;
  font-size: 13px;
  line-height: 1.6;
}

.entry-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.file-button {
  display: inline-flex;
}

.batch-panel {
  display: grid;
}

.batch-progress {
  display: grid;
  gap: 8px;
  padding: 16px 20px 6px;
}

.progress-meta {
  display: flex;
  justify-content: space-between;
  color: #6d788c;
  font-size: 12px;
}

.error-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 12px 20px 0;
  padding: 12px 14px;
  border: 1px solid #f3c0b4;
  border-radius: 6px;
  color: #8f2d1c;
  background: #fdf3f0;
}

.error-banner i {
  font-size: 18px;
}

.error-banner div {
  display: grid;
  gap: 3px;
  flex: 1;
  font-size: 12px;
}

.error-banner span {
  color: #a05a4d;
}

.batch-items {
  display: grid;
  gap: 12px;
  padding: 16px 20px;
}

.batch-item {
  padding: 14px;
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  background: #fafbfc;
}

.batch-item.conflict {
  border-color: #e7b865;
  background: #fffaf0;
}

.item-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.item-foot {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  margin-top: 8px;
  font-size: 12px;
}

.conflict-body {
  margin-top: 12px;
  display: grid;
  gap: 10px;
}

.conflict-fields {
  margin: 0;
  color: #9a6700;
  font-size: 12px;
  font-weight: 600;
}

.version-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.version-card {
  display: grid;
  gap: 8px;
  padding: 10px;
  border-radius: 6px;
  background: #fff;
}

.version-card.local {
  border: 1px solid #b8c4d4;
}

.version-card.incoming {
  border: 1px solid #8db79f;
}

.version-card header {
  font-size: 12px;
  font-weight: 700;
  color: #41506a;
}

.version-card pre {
  max-height: 190px;
  margin: 0;
  padding: 8px;
  overflow: auto;
  border-radius: 4px;
  background: #f3f5f8;
  color: #33405a;
  font-size: 10px;
  line-height: 1.5;
}

.hint {
  margin: 0;
  font-size: 11px;
}

.batch-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 12px 20px 18px;
  border-top: 1px solid #eef0f3;
}

.invalidation-note {
  display: flex;
  gap: 9px;
  align-items: center;
  color: #5f6a7e;
  font-size: 12px;
}

.invalidation-note i {
  color: #2f8f69;
}

.footer-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.history-list {
  display: grid;
}

.history-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 20px;
  border-bottom: 1px solid #eef0f3;
}

.history-item > div {
  display: flex;
  align-items: center;
  gap: 12px;
}

.history-stats {
  font-size: 12px;
}

.empty-panel {
  min-height: 160px;
  display: grid;
  place-items: center;
}

@media (max-width: 900px) {
  .import-entry,
  .batch-footer {
    flex-direction: column;
    align-items: stretch;
  }

  .version-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
