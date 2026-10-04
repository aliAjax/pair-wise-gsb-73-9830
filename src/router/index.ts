import { createRouter, createWebHistory } from 'vue-router'
import AppLayout from '@/layouts/AppLayout.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: AppLayout,
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('@/views/DashboardView.vue'),
        },
        {
          path: 'architecture',
          name: 'architecture',
          component: () => import('@/views/ArchitectureView.vue'),
        },
        {
          path: 'threats',
          name: 'threats',
          component: () => import('@/views/ThreatsView.vue'),
        },
        {
          path: 'risks',
          name: 'risks',
          component: () => import('@/views/RiskMatrixView.vue'),
        },
        {
          path: 'mitigations',
          name: 'mitigations',
          component: () => import('@/views/MitigationsView.vue'),
        },
        {
          path: 'reviews',
          name: 'reviews',
          component: () => import('@/views/ReviewsView.vue'),
        },
        {
          path: 'versions',
          name: 'versions',
          component: () => import('@/views/VersionsView.vue'),
        },
        {
          path: 'evidence',
          name: 'evidence',
          component: () => import('@/views/EvidenceView.vue'),
        },
        {
          path: 'imports',
          name: 'imports',
          component: () => import('@/views/ImportView.vue'),
        },
        {
          path: 'report',
          name: 'report',
          component: () => import('@/views/ReportView.vue'),
        },
      ],
    },
  ],
})

export default router
