<script setup lang="ts">
import { computed, ref } from 'vue'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import { riskLevel, riskScore } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const includeEvidence = ref(true)
const includeDecisions = ref(true)
const includeAudit = ref(false)

const report = computed(() => {
  const lines = [
    store.exportReport(),
    '',
    '## 控制证据',
    ...(includeEvidence.value
      ? store.data.evidence.map(
          (evidence) =>
            `- ${evidence.title}（${evidence.reference}，${evidence.collectedAt} 至 ${evidence.expiresAt}）`,
        )
      : ['- 未包含']),
    '',
    '## 会签意见',
    ...(includeDecisions.value
      ? store.data.decisions.map(
          (decision) =>
            `- ${decision.actor}/${decision.role}/${decision.decision}：${decision.comment}`,
        )
      : ['- 未包含']),
    '',
    '## 审计轨迹',
    ...(includeAudit.value
      ? store.data.audit.map(
          (event) => `- ${event.createdAt} ${event.actor} ${event.action}：${event.detail}`,
        )
      : ['- 未包含']),
  ]
  return lines.join('\n')
})

const downloadReport = (): void => {
  const blob = new Blob([report.value], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${store.data.boundary.name}-威胁建模报告-v1.${store.data.currentRevision}.md`
  anchor.click()
  URL.revokeObjectURL(url)
  toast.add({ severity: 'success', summary: '报告已导出', detail: 'Markdown 文件已生成', life: 2500 })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="交付物"
      title="导出评审报告"
      description="按需组合威胁、风险、证据、会签和审计信息，生成可归档的 Markdown 报告。"
    />

    <div class="report-layout">
      <aside class="report-options panel">
        <div class="panel-header">
          <h2 class="panel-title">报告范围</h2>
        </div>
        <div class="option-list">
          <label class="option-item">
            <Checkbox v-model="includeEvidence" binary />
            <span>
              <strong>控制证据</strong>
              <small>包含证据引用、有效期与责任人</small>
            </span>
          </label>
          <label class="option-item">
            <Checkbox v-model="includeDecisions" binary />
            <span>
              <strong>会签意见</strong>
              <small>包含开发、安全与业务负责人意见</small>
            </span>
          </label>
          <label class="option-item">
            <Checkbox v-model="includeAudit" binary />
            <span>
              <strong>审计轨迹</strong>
              <small>包含版本、风险接受和状态变更</small>
            </span>
          </label>
        </div>
        <div class="scope-summary">
          <div>
            <span>风险摘要</span>
            <strong>{{ store.data.risks.filter((risk) => risk.status !== 'closed').length }} 条开放</strong>
          </div>
          <div
            v-for="risk in [...store.data.risks]
              .filter((item) => item.status !== 'closed')
              .sort((a, b) => riskScore(b) - riskScore(a))
              .slice(0, 3)"
            :key="risk.id"
            class="scope-risk"
          >
            <span>{{ risk.code }} {{ risk.title }}</span>
            <StatusTag :value="riskLevel(riskScore(risk))" kind="severity" />
          </div>
        </div>
        <Button label="导出 Markdown" icon="pi pi-download" class="export-button" @click="downloadReport" />
      </aside>

      <section class="panel report-preview">
        <div class="panel-header">
          <h2 class="panel-title">报告预览</h2>
          <span class="muted">{{ report.length }} 字符</span>
        </div>
        <pre>{{ report }}</pre>
      </section>
    </div>
  </div>
</template>

<style scoped>
.report-layout {
  display: grid;
  grid-template-columns: 330px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.report-options {
  position: sticky;
  top: 82px;
  padding-bottom: 16px;
}

.option-list {
  display: grid;
  gap: 1px;
  background: #e9ecf1;
}

.option-item {
  display: flex;
  align-items: flex-start;
  gap: 11px;
  padding: 14px 16px;
  background: #fff;
  cursor: pointer;
}

.option-item > span {
  display: grid;
  gap: 4px;
}

.option-item strong {
  font-size: 13px;
}

.option-item small {
  color: #707b8e;
  font-size: 11px;
  line-height: 1.45;
}

.scope-summary {
  display: grid;
  gap: 10px;
  padding: 16px;
}

.scope-summary > div:first-child {
  display: flex;
  justify-content: space-between;
  color: #5e697d;
  font-size: 12px;
}

.scope-risk {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  font-size: 11px;
}

.scope-risk > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.export-button {
  margin: 0 16px;
  width: calc(100% - 32px);
}

.report-preview {
  overflow: hidden;
}

.report-preview pre {
  max-height: calc(100vh - 168px);
  margin: 0;
  padding: 20px;
  overflow: auto;
  color: #2f3a4d;
  background: #fbfcfd;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
}
</style>
