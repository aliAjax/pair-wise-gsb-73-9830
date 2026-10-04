<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { MitigationTask } from '@/models/domain'
import { createId } from '@/services/repository'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const statusFilter = ref<string | null>(null)
const editorVisible = ref(false)

const actionOptions = [
  { label: '限制访问', value: 'restrict' },
  { label: '持续监测', value: 'monitor' },
  { label: '加密保护', value: 'encrypt' },
  { label: '隔离处置', value: 'isolate' },
  { label: '有条件放行', value: 'allow_with_condition' },
]
const statusOptions = [
  { label: '待处理', value: 'todo' },
  { label: '进行中', value: 'in_progress' },
  { label: '验证中', value: 'verifying' },
  { label: '已完成', value: 'done' },
]

const form = reactive<MitigationTask>({
  id: '',
  threatId: '',
  title: '',
  owner: '',
  dueAt: '',
  status: 'todo',
  action: 'restrict',
  detail: '',
  evidenceIds: [],
  conflictGroup: '',
})

const filteredTasks = computed(() =>
  statusFilter.value
    ? store.data.mitigations.filter((task) => task.status === statusFilter.value)
    : store.data.mitigations,
)

const conflictTaskIds = computed(() => {
  const conflicts = store.issues.filter((issue) => issue.kind === 'mitigation_conflict')
  const threatIds = new Set(conflicts.map((issue) => issue.entityId))
  return new Set(
    store.data.mitigations
      .filter((task) => threatIds.has(task.threatId) && task.conflictGroup)
      .map((task) => task.id),
  )
})

const threatLabel = (id: string): string => {
  const threat = store.data.threats.find((item) => item.id === id)
  return threat ? `${threat.code} ${threat.title}` : id
}

const openEditor = (task?: MitigationTask): void => {
  Object.assign(
    form,
    task
      ? structuredClone(task)
      : {
          id: '',
          threatId: store.data.threats[0]?.id ?? '',
          title: '',
          owner: '',
          dueAt: '',
          status: 'todo',
          action: 'restrict',
          detail: '',
          evidenceIds: [],
          conflictGroup: '',
        },
  )
  editorVisible.value = true
}

const saveTask = (): void => {
  if (!form.title.trim() || !form.threatId || !form.owner.trim() || !form.dueAt) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '威胁、任务、负责人和截止日期不能为空', life: 3000 })
    return
  }
  store.saveEntity('mitigations', { ...form, id: form.id || createId('mit') })
  editorVisible.value = false
  toast.add({ severity: 'success', summary: '缓解任务已保存', detail: form.title, life: 2500 })
}

const nextStatus = (status: MitigationTask['status']): MitigationTask['status'] => {
  const sequence: MitigationTask['status'][] = ['todo', 'in_progress', 'verifying', 'done']
  return sequence[Math.min(sequence.indexOf(status) + 1, sequence.length - 1)]
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="缓解执行"
      title="缓解任务与冲突检查"
      description="维护各威胁的处置动作、负责人、期限和证据；同一威胁下互斥策略会被自动标记。"
    />

    <section v-if="conflictTaskIds.size > 0" class="conflict-banner">
      <i class="pi pi-exclamation-triangle"></i>
      <div>
        <strong>检测到互斥缓解措施</strong>
        <span>同一威胁同时存在限制访问与有条件放行，请统一处置方向后再进入会签。</span>
      </div>
    </section>

    <section class="panel filter-panel">
      <div class="toolbar-row">
        <div class="toolbar-field">
          <span>任务状态</span>
          <Select
            v-model="statusFilter"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            placeholder="全部状态"
            show-clear
          />
        </div>
        <div class="filter-actions">
          <Button label="新增任务" icon="pi pi-plus" @click="openEditor()" />
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">缓解任务 {{ filteredTasks.length }} 条</h2>
      </div>
      <DataTable :value="filteredTasks" dataKey="id" size="small" stripedRows>
        <Column header="关联威胁" style="min-width: 230px">
          <template #body="{ data }">
            <strong>{{ threatLabel(data.threatId) }}</strong>
          </template>
        </Column>
        <Column field="title" header="缓解措施" style="min-width: 230px" />
        <Column header="动作" style="width: 125px">
          <template #body="{ data }">
            {{ actionOptions.find((item) => item.value === data.action)?.label }}
          </template>
        </Column>
        <Column field="owner" header="负责人" style="width: 120px" />
        <Column field="dueAt" header="截止日" style="width: 115px" />
        <Column header="状态" style="width: 110px">
          <template #body="{ data }">
            <div class="status-cell">
              <StatusTag :value="data.status" kind="status" />
              <span v-if="conflictTaskIds.has(data.id)" class="conflict-label">冲突</span>
            </div>
          </template>
        </Column>
        <Column header="操作" style="width: 200px">
          <template #body="{ data }">
            <Button label="编辑" size="small" text @click="openEditor(data)" />
            <Button
              v-if="data.status !== 'done'"
              label="推进"
              icon="pi pi-arrow-right"
              size="small"
              text
              @click="store.updateMitigationStatus(data.id, nextStatus(data.status))"
            />
          </template>
        </Column>
      </DataTable>
    </section>

    <Dialog
      v-model:visible="editorVisible"
      :header="form.id ? '编辑缓解任务' : '新增缓解任务'"
      modal
      :style="{ width: '760px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>关联威胁</label>
          <Select
            v-model="form.threatId"
            :options="store.data.threats"
            option-label="title"
            option-value="id"
            filter
          />
        </div>
        <div class="field field-wide">
          <label>任务名称</label>
          <InputText v-model="form.title" />
        </div>
        <div class="field">
          <label>处置动作</label>
          <Select
            v-model="form.action"
            :options="actionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>任务状态</label>
          <Select
            v-model="form.status"
            :options="statusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="form.owner" />
        </div>
        <div class="field">
          <label>截止日期</label>
          <InputText v-model="form.dueAt" type="date" />
        </div>
        <div class="field">
          <label>冲突检查组</label>
          <InputText
            v-model="form.conflictGroup"
            placeholder="同一威胁同一组的互斥动作会触发提醒"
          />
        </div>
        <div class="field">
          <label>关联证据</label>
          <MultiSelect
            v-model="form.evidenceIds"
            :options="store.data.evidence"
            option-label="title"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field field-wide">
          <label>执行说明</label>
          <Textarea v-model="form.detail" rows="4" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="editorVisible = false" />
        <Button label="保存任务" icon="pi pi-check" @click="saveTask" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.filter-panel {
  padding: 14px 16px;
}

.conflict-banner {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  padding: 14px 16px;
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  background: #fffaf0;
}

.conflict-banner > i {
  margin-top: 2px;
  color: #b45309;
}

.conflict-banner > div {
  display: grid;
  gap: 4px;
}

.conflict-banner span {
  color: #7b5d2c;
  font-size: 12px;
}

.status-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.conflict-label {
  color: #b45309;
  font-size: 11px;
  font-weight: 700;
}
</style>
