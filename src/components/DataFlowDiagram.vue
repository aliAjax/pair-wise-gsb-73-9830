<script setup lang="ts">
import { computed } from 'vue'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()

const nodeWidth = 174
const nodeHeight = 66
const columns = computed(() => {
  const grouped = new Map<string, typeof store.data.components>()
  store.data.zones.forEach((zone) => grouped.set(zone.id, []))
  store.data.components.forEach((component) => {
    const group = grouped.get(component.zoneId) ?? []
    group.push(component)
    grouped.set(component.zoneId, group)
  })
  return [...grouped.entries()]
})

const nodePositions = computed<Record<string, { x: number; y: number }>>(() => {
  const result: Record<string, { x: number; y: number }> = {}
  columns.value.forEach(([, components], columnIndex) => {
    components.forEach((component, rowIndex) => {
      result[component.id] = {
        x: 36 + columnIndex * 236,
        y: 74 + rowIndex * 104,
      }
    })
  })
  return result
})

const diagramHeight = computed(() => {
  const maxRows = Math.max(...columns.value.map(([, components]) => components.length), 1)
  return Math.max(480, maxRows * 104 + 150)
})

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? id
</script>

<template>
  <div class="diagram-shell">
    <svg
      class="diagram"
      :viewBox="`0 0 976 ${diagramHeight}`"
      role="img"
      aria-label="系统组件与数据流图"
    >
      <defs>
        <marker
          id="arrowhead"
          markerWidth="8"
          markerHeight="6"
          refX="7"
          refY="3"
          orient="auto"
        >
          <polygon points="0 0, 8 3, 0 6" fill="#6b7890" />
        </marker>
      </defs>
      <g
        v-for="([zoneId, components], columnIndex) in columns"
        :key="zoneId"
      >
        <rect
          :x="18 + columnIndex * 236"
          y="18"
          width="210"
          :height="diagramHeight - 36"
          rx="6"
          fill="#f8fafc"
          stroke="#dfe5ed"
        />
        <text
          :x="123 + columnIndex * 236"
          y="48"
          text-anchor="middle"
          fill="#536078"
          font-size="13"
          font-weight="700"
        >
          {{ store.data.zones.find((zone) => zone.id === zoneId)?.name }}
        </text>
        <g
          v-for="(component, rowIndex) in components"
          :key="component.id"
          :transform="`translate(${36 + columnIndex * 236}, ${74 + rowIndex * 104})`"
        >
          <rect
            :width="nodeWidth"
            :height="nodeHeight"
            rx="6"
            fill="#ffffff"
            :stroke="component.criticality === 'critical' ? '#d97706' : '#cfd7e3'"
            stroke-width="1.4"
          />
          <text x="12" y="25" fill="#20293a" font-size="13" font-weight="700">
            {{ component.name }}
          </text>
          <text x="12" y="47" fill="#728096" font-size="11">
            {{ component.type }} · {{ component.owner }}
          </text>
        </g>
      </g>
      <g v-for="flow in store.data.flows" :key="flow.id">
        <line
          v-if="nodePositions[flow.sourceId] && nodePositions[flow.targetId]"
          :x1="nodePositions[flow.sourceId].x + nodeWidth"
          :y1="nodePositions[flow.sourceId].y + nodeHeight / 2"
          :x2="nodePositions[flow.targetId].x"
          :y2="nodePositions[flow.targetId].y + nodeHeight / 2"
          stroke="#6b7890"
          stroke-width="1.4"
          marker-end="url(#arrowhead)"
          opacity="0.72"
        />
        <text
          v-if="nodePositions[flow.sourceId] && nodePositions[flow.targetId]"
          :x="
            (nodePositions[flow.sourceId].x +
              nodeWidth +
              nodePositions[flow.targetId].x) /
            2
          "
          :y="
            (nodePositions[flow.sourceId].y +
              nodeHeight / 2 +
              nodePositions[flow.targetId].y +
              nodeHeight / 2) /
              2 -
            8
          "
          text-anchor="middle"
          fill="#526077"
          font-size="10"
        >
          {{ flow.protocol }}
        </text>
      </g>
      <line
        x1="228"
        y1="8"
        x2="228"
        :y2="diagramHeight - 8"
        stroke="#c5ccd7"
        stroke-width="1"
        stroke-dasharray="5 4"
      />
      <line
        x1="464"
        y1="8"
        x2="464"
        :y2="diagramHeight - 8"
        stroke="#c5ccd7"
        stroke-width="1"
        stroke-dasharray="5 4"
      />
      <line
        x1="700"
        y1="8"
        x2="700"
        :y2="diagramHeight - 8"
        stroke="#c5ccd7"
        stroke-width="1"
        stroke-dasharray="5 4"
      />
    </svg>
    <div class="legend">
      <span><i class="legend-line"></i>数据流方向</span>
      <span><i class="legend-critical"></i>关键组件</span>
      <span>虚线：信任区边界</span>
    </div>
    <div class="flow-index">
      <div v-for="flow in store.data.flows" :key="flow.id" class="flow-index-item">
        <strong>{{ flow.name }}</strong>
        <span>{{ componentName(flow.sourceId) }} → {{ componentName(flow.targetId) }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.diagram-shell {
  overflow: auto;
}

.diagram {
  display: block;
  min-width: 976px;
  width: 100%;
  background: #fff;
}

.legend {
  display: flex;
  gap: 22px;
  padding: 10px 18px;
  border-top: 1px solid #e5e9ef;
  color: #667188;
  font-size: 12px;
}

.legend span {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.legend-line {
  width: 18px;
  height: 2px;
  background: #6b7890;
}

.legend-critical {
  width: 14px;
  height: 9px;
  border: 2px solid #d97706;
  border-radius: 3px;
}

.flow-index {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1px;
  background: #e5e9ef;
  border-top: 1px solid #e5e9ef;
}

.flow-index-item {
  display: grid;
  gap: 4px;
  padding: 11px 16px;
  background: #fff;
  font-size: 12px;
}

.flow-index-item span {
  color: #6d788c;
}
</style>
