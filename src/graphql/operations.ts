import { gql } from '@apollo/client/core'

export const DASHBOARD_METRICS_QUERY = gql`
  query DashboardMetrics {
    dashboardMetrics {
      components
      threats
      critical
      coverage
      openIssues
      pendingReviews
    }
  }
`

export const THREAT_INDEX_QUERY = gql`
  query ThreatIndex {
    threatIndex {
      id
      code
      title
      severity
      status
      reviewStatus
      componentCount
      controlCount
    }
  }
`

export const CONTROL_HEALTH_QUERY = gql`
  query ControlHealth {
    controlHealth {
      total
      effective
      degraded
      failed
      missingEvidence
    }
  }
`
