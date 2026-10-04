<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Message from 'primevue/message'
import ProgressBar from 'primevue/progressbar'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import { useDashboardGraphql } from '@/composables/useDashboardGraphql'
import { riskLevel, riskScore } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const { metrics, loading, error, load } = useDashboardGraphql()

onMounted(load)

const topRisks = computed(() =>
  [...store.data.risks]
    .filter((risk) => risk.status !== 'closed')
    .sort((a, b) => riskScore(b) - riskScore(a))
    .slice(0, 5),
)

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? id
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="安全评审工作区"
      title="威胁建模工作台"
      description="集中查看当前模型覆盖、控制健康度、风险接受与待会签事项。"
    />

    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <div class="metrics-grid">
      <div class="metric">
        <div class="metric-label">建模组件</div>
        <div class="metric-value">{{ metrics?.components ?? store.metrics.components }}</div>
        <div class="metric-note">{{ store.data.flows.length }} 条数据流已登记</div>
      </div>
      <div class="metric">
        <div class="metric-label">开放严重威胁</div>
        <div class="metric-value severity-critical">
          {{ metrics?.critical ?? store.metrics.critical }}
        </div>
        <div class="metric-note">严重级别且尚未完成缓解</div>
      </div>
      <div class="metric">
        <div class="metric-label">威胁覆盖率</div>
        <div class="metric-value">{{ metrics?.coverage ?? store.metrics.coverage }}%</div>
        <ProgressBar
          :value="metrics?.coverage ?? store.metrics.coverage"
          :show-value="false"
          class="coverage-bar"
        />
      </div>
      <div class="metric">
        <div class="metric-label">待会签</div>
        <div class="metric-value">{{ metrics?.pendingReviews ?? store.metrics.pendingReviews }}</div>
        <div class="metric-note">{{ metrics?.openIssues ?? store.metrics.openIssues }} 项模型校验未关闭</div>
      </div>
    </div>

    <div class="dashboard-grid">
      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">需要优先处理</h2>
          <RouterLink to="/threats" class="text-link">查看全部威胁</RouterLink>
        </div>
        <div class="issue-list">
          <article v-for="issue in store.issues.slice(0, 6)" :key="issue.id" class="issue-row">
            <StatusTag :value="issue.severity" kind="severity" />
            <div>
              <strong>{{ issue.title }}</strong>
              <p>{{ issue.detail }}</p>
            </div>
            <RouterLink
              :to="issue.kind === 'mitigation_conflict' ? '/mitigations' : '/risks'"
              class="row-link"
            >
              处理
            </RouterLink>
          </article>
          <div v-if="store.issues.length === 0" class="empty-state">当前没有模型校验问题。</div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">版本与会签</h2>
          <RouterLink to="/reviews" class="text-link">进入会签中心</RouterLink>
        </div>
        <div class="review-list">
          <article v-for="threat in store.pendingReviews" :key="threat.id" class="review-row">
            <div class="review-code">{{ threat.code }}</div>
            <div class="review-main">
              <strong>{{ threat.title }}</strong>
              <span>
                v1.{{ threat.revision }} ·
                {{ store.reviewProgress(store.data.decisions.filter((decision) => decision.threatId === threat.id && decision.revision === threat.revision)) }}%
                会签进度
              </span>
            </div>
            <span class="muted">{{ threat.componentIds.map(componentName).join(' / ') }}</span>
          </article>
          <div v-if="store.pendingReviews.length === 0" class="empty-state">没有待会签威胁。</div>
        </div>
      </section>
    </div>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">高优先级风险</h2>
        <div class="panel-actions">
          <Button
            label="刷新 GraphQL 指标"
            icon="pi pi-refresh"
            severity="secondary"
            text
            :loading="loading"
            @click="load"
          />
          <RouterLink to="/risks">
            <Button label="风险矩阵" icon="pi pi-th-large" outlined />
          </RouterLink>
        </div>
      </div>
      <DataTable :value="topRisks" size="small" stripedRows>
        <Column field="code" header="风险编号" style="width: 110px" />
        <Column field="title" header="风险" />
        <Column header="评分" style="width: 120px">
          <template #body="{ data }">
            <strong>{{ riskScore(data) }}</strong>
            <StatusTag :value="riskLevel(riskScore(data))" kind="severity" class="score-tag" />
          </template>
        </Column>
        <Column field="owner" header="负责人" style="width: 150px" />
        <Column header="状态" style="width: 120px">
          <template #body="{ data }">
            <StatusTag :value="data.status" kind="status" />
          </template>
        </Column>
        <Column header="接受到期" style="width: 140px">
          <template #body="{ data }">
            {{ data.acceptanceExpiresAt ?? '-' }}
          </template>
        </Column>
      </DataTable>
    </section>
  </div>
</template>

<style scoped>
.coverage-bar {
  height: 5px;
  margin-top: 14px;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(360px, 0.8fr);
  gap: 16px;
}

.issue-list,
.review-list {
  padding: 0 16px 8px;
}

.issue-row {
  display: grid;
  grid-template-columns: 62px minmax(0, 1fr) 50px;
  gap: 12px;
  align-items: start;
  padding: 14px 0;
  border-bottom: 1px solid #edf0f4;
}

.issue-row:last-child,
.review-row:last-child {
  border-bottom: 0;
}

.issue-row strong,
.review-row strong {
  font-size: 13px;
}

.issue-row p {
  margin: 5px 0 0;
  color: #667188;
  font-size: 12px;
  line-height: 1.5;
}

.row-link,
.text-link {
  color: #3268a6;
  font-size: 13px;
  text-decoration: none;
}

.review-row {
  display: grid;
  grid-template-columns: 58px minmax(0, 1fr);
  gap: 10px;
  padding: 14px 0;
  border-bottom: 1px solid #edf0f4;
}

.review-code {
  color: #3268a6;
  font-family: monospace;
  font-size: 12px;
  font-weight: 700;
}

.review-main {
  display: grid;
  gap: 5px;
}

.review-row > .muted {
  grid-column: 2;
  font-size: 11px;
}

.panel-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.score-tag {
  margin-left: 8px;
}
</style>
