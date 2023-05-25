import {IgnoreConfig, IgnoreEntry, Severity, TargetSpecificIgnoreConfig, TrivyReport, TrivyResult} from "./types";
import * as fs from 'fs';

export function parseReport(reportFilePath: string, ignoreFilePath: string): TrivyResult[] {
  const report = JSON.parse(fs.readFileSync(reportFilePath).toString()) as TrivyReport
  const ignoreConf = JSON.parse(fs.readFileSync(ignoreFilePath).toString()) as IgnoreConfig

  return report.Results.map(result => enrichResultWithIgnoreHints(result, ignoreConf))
      .filter(result => {
        return result.Vulnerabilities.length > 0 || result.Misconfigurations.length > 0
      })

}

function enrichResultWithIgnoreHints(result: TrivyResult, ignoreConf: IgnoreConfig): TrivyResult {
  const vulnerabilitiesWithIgnoreAnnotation = (result.Vulnerabilities || [])
      .map(vulnerability => {
        let vulnerabilityIgnore = getIgnoreInfo(ignoreConf, result.Target, vulnerability.VulnerabilityID)

        if (!vulnerabilityIgnore) {
          return vulnerability
        } else {
          return {
            ...vulnerability,
            Severity: Severity.IGNORED,
            IgnoreReason: vulnerabilityIgnore.reason,
            RevisitAt: vulnerabilityIgnore.revisitAt
          }
        }
      });

  const misconfigurationsWithIgnoreAnnotation = (result.Misconfigurations || [])
      .map(misconfiguration => {
        let misconfigurationIgnore = getIgnoreInfo(ignoreConf, result.Target, misconfiguration.ID, misconfiguration.Message)
        if (!misconfigurationIgnore) {
          return misconfiguration
        } else {
          return {
            ...misconfiguration,
            Severity: Severity.IGNORED,
            IgnoreReason: misconfigurationIgnore.reason,
            RevisitAt: misconfigurationIgnore.revisitAt
          }
        }
      });

  return {
    ...result,
    Vulnerabilities: vulnerabilitiesWithIgnoreAnnotation,
    Misconfigurations: misconfigurationsWithIgnoreAnnotation
  };
}

function getIgnoreInfo(ignoreConf: IgnoreConfig, targetName: string, expectedId: string, message = ''): IgnoreEntry | undefined {
  const globalIgnore: IgnoreEntry | undefined = (ignoreConf.ignore || []).find(({id}) => id === expectedId)

  if (globalIgnore && globalIgnore.revisitAt === undefined) {
    console.error('All global ignores need an expiration date. It is missing for ', expectedId)
    process.exit(1)
  }

  if (globalIgnore && (globalIgnore.revisitAt === 'never' || Date.now() <= Date.parse(globalIgnore.revisitAt))) {
    return globalIgnore
  }

  let misconfigurationMessage = message
  let targetSpecific = (ignoreConf.targetSpecific || [] as TargetSpecificIgnoreConfig[]).find(target => {
    if (target.resource && target.resourceName && target.container) {
      return target.target === targetName &&
          misconfigurationMessage.includes("Container '" + target.container + "'") &&
          misconfigurationMessage.includes(target.resource + " '" + target.resourceName + "'")
    }

    return target.target === targetName
  })

  if (targetSpecific === undefined) {
    return undefined
  }

  const matchingRule = targetSpecific.ignore.find(({id}) => id === expectedId)

  if (!matchingRule) {
    return undefined
  }

  if (matchingRule.revisitAt === undefined) {
    console.error('All target specific ignores need an expiration date. It is missing for ', targetName, expectedId)
    process.exit(1)
  }

  if (matchingRule.revisitAt !== 'never' && Date.now() > Date.parse(matchingRule.revisitAt)) {
    return undefined
  }

  if (matchingRule) {
    return matchingRule
  }

  return undefined
}
