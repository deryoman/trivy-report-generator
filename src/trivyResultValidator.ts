import {Severity, TrivyResult} from "./types";

export function trivyResultValidator(results: TrivyResult[]) {
  let hasError = false
  for (const result of results) {
    for (const vulnerability of result.Vulnerabilities) {
      if (vulnerability.Severity !== Severity.IGNORED) {
        console.log(vulnerability)
        hasError = true
      }
    }

    for (const misconfiguration of result.Misconfigurations) {
      if (misconfiguration.Severity !== Severity.IGNORED) {
        console.log(misconfiguration)
        hasError = true
      }
    }
  }

  if (hasError) {
    process.exit(1)
  } else {
    console.log(`No vulnerabilities or misconfigurations found`)
  }
}