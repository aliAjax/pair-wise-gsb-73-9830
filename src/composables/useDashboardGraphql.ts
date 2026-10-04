import { ref } from 'vue'
import { apolloClient } from '@/graphql/client'
import { DASHBOARD_METRICS_QUERY } from '@/graphql/operations'
import type { DashboardMetrics } from '@/services/selectors'

export const useDashboardGraphql = () => {
  const metrics = ref<DashboardMetrics | null>(null)
  const loading = ref(false)
  const error = ref('')

  const load = async (): Promise<void> => {
    loading.value = true
    error.value = ''
    try {
      const result = await apolloClient.query<{ dashboardMetrics: DashboardMetrics }>({
        query: DASHBOARD_METRICS_QUERY,
        fetchPolicy: 'no-cache',
      })
      metrics.value = result.data.dashboardMetrics
    } catch (caught) {
      error.value = caught instanceof Error ? caught.message : 'GraphQL 指标读取失败'
    } finally {
      loading.value = false
    }
  }

  return { metrics, loading, error, load }
}
