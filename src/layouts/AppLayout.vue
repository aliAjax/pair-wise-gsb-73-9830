<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useConfirm } from 'primevue/useconfirm'
import Button from 'primevue/button'
import { useThreatModelStore } from '@/stores/threatModel'

const router = useRouter()
const confirm = useConfirm()
const store = useThreatModelStore()

const navigation = [
  { label: '工作台', icon: 'pi pi-chart-line', to: '/' },
  { label: '架构与边界', icon: 'pi pi-sitemap', to: '/architecture' },
  { label: '威胁清单', icon: 'pi pi-shield', to: '/threats' },
  { label: '风险矩阵', icon: 'pi pi-th-large', to: '/risks' },
  { label: '缓解任务', icon: 'pi pi-list-check', to: '/mitigations' },
  { label: '会签中心', icon: 'pi pi-verified', to: '/reviews' },
  { label: '版本差异', icon: 'pi pi-code', to: '/versions' },
  { label: '控制证据', icon: 'pi pi-folder-open', to: '/evidence' },
  { label: '交换包导入', icon: 'pi pi-box', to: '/imports' },
  { label: '导出报告', icon: 'pi pi-file-export', to: '/report' },
]

const reset = (): void => {
  confirm.require({
    header: '恢复演示基线',
    message: '当前本地修改将被清除，是否继续？',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '恢复',
    rejectLabel: '取消',
    accept: () => {
      store.resetDemo()
      void router.push('/')
    },
  })
}
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark">SX</span>
        <div>
          <strong>SCAPEX</strong>
          <small>威胁建模与会签</small>
        </div>
      </div>
      <nav class="nav-list">
        <RouterLink
          v-for="item in navigation"
          :key="item.to"
          :to="item.to"
          class="nav-item"
          :class="{ active: $route.path === item.to }"
        >
          <i :class="item.icon"></i>
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>
      <div class="sidebar-foot">
        <span>本地持久化</span>
        <strong>状态已自动保存</strong>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar">
        <div>
          <strong>{{ store.data.boundary.name }}</strong>
          <span>当前基线 v1.{{ store.data.currentRevision }}</span>
        </div>
        <div class="topbar-actions">
          <span class="sync-state">
            <i class="pi pi-cloud-upload"></i>
            最后保存 {{ new Date(store.lastSavedAt).toLocaleTimeString('zh-CN') }}
          </span>
          <Button label="恢复基线" icon="pi pi-history" severity="secondary" outlined @click="reset" />
        </div>
      </header>
      <section class="content-shell">
        <div v-if="store.recoveryNotice" class="global-recovery" @click="router.push('/imports')">
          <i class="pi pi-history"></i>
          <span>
            导入批次写入中断，已保留完整检查点（{{ store.recoveryNotice.appliedCount
            }}/{{ store.recoveryNotice.totalCount }}），点击前往续做。
          </span>
        </div>
        <RouterView />
      </section>
    </main>
  </div>
</template>

<style scoped>
.app-shell {
  display: grid;
  grid-template-columns: 232px minmax(0, 1fr);
  min-height: 100vh;
}

.sidebar {
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 18px 14px;
  color: #d9e1ec;
  background: #172235;
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 4px 8px 22px;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 6px;
  color: #172235;
  background: #7dd3b0;
  font-size: 13px;
  font-weight: 800;
}

.brand div {
  display: grid;
  gap: 3px;
}

.brand strong {
  color: #fff;
  font-size: 15px;
  letter-spacing: 0.06em;
}

.brand small {
  color: #8492a8;
  font-size: 11px;
}

.nav-list {
  display: grid;
  gap: 4px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 40px;
  padding: 0 11px;
  border-radius: 5px;
  color: #aeb9ca;
  font-size: 13px;
  text-decoration: none;
}

.nav-item i {
  width: 16px;
  font-size: 14px;
}

.nav-item:hover {
  color: #fff;
  background: #22324b;
}

.nav-item.active {
  color: #fff;
  background: #2b4365;
  box-shadow: inset 3px 0 #7dd3b0;
}

.sidebar-foot {
  display: grid;
  gap: 5px;
  margin-top: auto;
  padding: 13px 10px;
  border-top: 1px solid #2b374a;
  color: #7f8da2;
  font-size: 11px;
}

.sidebar-foot strong {
  color: #aeb9ca;
  font-size: 12px;
}

.main-shell {
  min-width: 0;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 64px;
  padding: 0 24px;
  border-bottom: 1px solid #dde2e9;
  background: rgba(255, 255, 255, 0.96);
}

.topbar > div:first-child {
  display: grid;
  gap: 4px;
}

.topbar strong {
  font-size: 14px;
}

.topbar span {
  color: #717c90;
  font-size: 12px;
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 16px;
}

.sync-state {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.content-shell {
  max-width: 1560px;
  padding: 24px;
}

.global-recovery {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
  padding: 10px 14px;
  border: 1px solid #e0b341;
  border-radius: 6px;
  color: #7a5a12;
  background: #fff8e6;
  font-size: 12px;
  cursor: pointer;
}

.global-recovery:hover {
  background: #fdf2d0;
}
</style>
