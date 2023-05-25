import {IgnoreConfig, IgnoreEntry, TargetSpecificIgnoreConfig, TrivyReport} from "./types";
import * as fs from 'fs';

interface CveSummary {
  globalCveIds: string[]
  cveIdsByTarget: Map<string, string[]>
}

export function reportRedundantIgnore(ignoreFilePath: string) {
  const ignoreConf = JSON.parse(fs.readFileSync(ignoreFilePath).toString()) as IgnoreConfig
  const ignoredCveIds = (ignoreConf.ignore || []).map(ignoreEntry => ignoreEntry.id)
  const duplicateCveIdEntries = ignoredCveIds.filter((cveId, index) => index !== ignoredCveIds.indexOf(cveId));
  if (duplicateCveIdEntries.length > 0) {
    console.error('Some CVEs have multiple ignore entries, which causes inconsistent behavior. Fix ignore file to have at most one ignore entry per CVE.', duplicateCveIdEntries)
    process.exit(1)
  }
}

export function reportUnusedIgnores(ignoreFilePath: string, trivyReportsDirectory: string) {
  const cveSummary = extractCveSummary(trivyReportsDirectory);
  const ignoreConf = JSON.parse(fs.readFileSync(ignoreFilePath).toString()) as IgnoreConfig

  const unusedGlobalIgnores: IgnoreEntry[] = determineUnusedGlobalIgnores(ignoreConf, cveSummary)
  const unusedIgnoresByTarget: TargetSpecificIgnoreConfig[] = determineUnusedIgnoresByTarget(ignoreConf, cveSummary)

  if (unusedGlobalIgnores.length > 0) {
    unusedGlobalIgnores.forEach(ignore => console.error("unused global ignore: ", ignore))
  }
  if (unusedIgnoresByTarget.length > 0) {
    unusedIgnoresByTarget.forEach(ignore => console.error("unused target specific ignore: ", ignore))
  }
  if (unusedGlobalIgnores.length > 0 || unusedIgnoresByTarget.length > 0) {
    process.exit(1)
  }
}

function determineUnusedGlobalIgnores(ignoreConf: IgnoreConfig, cveSummary: CveSummary): IgnoreEntry[] {
  return (ignoreConf.ignore || []).filter(ignore => !cveSummary.globalCveIds.includes(ignore.id));
}

function determineUnusedIgnoresByTarget(ignoreConf: IgnoreConfig, cveSummary: CveSummary) {
  return (ignoreConf.targetSpecific || []).map(targetSpecificIgnoreConfig => {
    const actualCvesOnTarget = cveSummary.cveIdsByTarget.get(targetSpecificIgnoreConfig.target) || [];
    return {
      ...targetSpecificIgnoreConfig,
      ignore: targetSpecificIgnoreConfig.ignore.filter(ignore => !actualCvesOnTarget.includes(ignore.id))
    }
  }).filter(unusedTargetSpecificIgnoreConfig => unusedTargetSpecificIgnoreConfig.ignore.length > 0);
}

function extractCveSummary(trivyReportsDirectory: string): CveSummary {
  const trivyReportsDirectoryContents = fs.readdirSync(trivyReportsDirectory);
  const directoryWithTrailingSlash = trivyReportsDirectory + (trivyReportsDirectory.endsWith("/") ? "" : "/");
  const trivyReportPaths = trivyReportsDirectoryContents.filter(path => path.endsWith(".json")).map(filename => directoryWithTrailingSlash + filename);
  const trivyReports = trivyReportPaths.map(path => JSON.parse(fs.readFileSync(path).toString()) as TrivyReport)

  const globalCveIds: string[] = []
  const cveIdsByTarget: Map<string, string[]> = new Map<string, string[]>()
  trivyReports.flatMap(report => report.Results || []).flatMap(result => (result.Misconfigurations || []).forEach(misconfig => {
    globalCveIds.push(misconfig.ID)
    const targetSpecificCveIds = cveIdsByTarget.get(result.Target) || [];
    targetSpecificCveIds.push(misconfig.ID);
    cveIdsByTarget.set(result.Target, targetSpecificCveIds)
  }))
  trivyReports.flatMap(report => report.Results || []).flatMap(result => (result.Vulnerabilities || []).forEach(vulnerability => {
    globalCveIds.push(vulnerability.VulnerabilityID)
    const targetSpecificCveIds = cveIdsByTarget.get(result.Target) || [];
    targetSpecificCveIds.push(vulnerability.VulnerabilityID);
    cveIdsByTarget.set(result.Target, targetSpecificCveIds)
  }))

  return {
    globalCveIds,
    cveIdsByTarget
  }
}

function ignoreIsUsed(ignore: IgnoreEntry, misconfigurationIds: string[], vulnerabilityIds: string[]): boolean {
  return misconfigurationIds.includes(ignore.id) || vulnerabilityIds.includes(ignore.id);
}
