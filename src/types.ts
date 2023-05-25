export enum Severity {
  "UNKNOWN",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
  "IGNORED"
}

export interface IgnoreConfig {
  ignore?: IgnoreEntry[]
  targetSpecific?: TargetSpecificIgnoreConfig[]
}

export interface TargetSpecificIgnoreConfig {
  target: string
  ignore: IgnoreEntry[]
  resource?: string
  resourceName?: string
  container?: string
}

export interface IgnoreEntry {
  id: string
  revisitAt: string
  reason: string
}

export interface TrivyReport {
  Results: TrivyResult[]
}

export interface TrivyResult {
  Vulnerabilities: Vulnerability[]
  Misconfigurations: Misconfiguration[]
  Target: string
  Type: string
}

export interface Vulnerability {
  VulnerabilityID: string
  PkgName: string
  PkgPath: string
  InstalledVersion: string
  IgnoreReason: string
  FixedVersion: string
  References: string[]
  Severity: Severity
  RevisitAt?: string
}

export interface Misconfiguration {
  ID: string
  Message: string
  Severity: Severity
  IgnoreReason: string
  PrimaryURL: string
  Title: string
  RevisitAt?: string
}