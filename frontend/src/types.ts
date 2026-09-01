export type Json = Record<string, unknown>

export type Session = {
  accessToken: string
  refreshToken: string
  user: Json
}

export type ListResponse = {
  items?: Json[]
  count?: number
}

export type Page =
  | 'overview'
  | 'upload'
  | 'current'
  | 'analyses'
  | 'incidents'
  | 'case'
  | 'assistant'
  | 'audit'
  | 'rules'
  | 'quality'
  | 'attack'
  | 'graph'
  | 'connectors'
  | 'reports'
  | 'ragadmin'
  | 'securityadmin'
  | 'system'
  | 'realtime'
  | 'intel'
  | 'hunts'
  | 'caseops'
  | 'response'
  | 'detections'
  | 'identity'
  | 'graphintel'

export type NavigationContext = {
  page: Page
  analysisId: string
  incidentId: string
}
