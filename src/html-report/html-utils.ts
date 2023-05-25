import {Misconfiguration, Severity, Vulnerability} from "../types";

export function renderSeverity(rule: Vulnerability | Misconfiguration): string {
  const severity = rule.Severity;
  let text;

  if (severity === Severity.IGNORED) {
    text = 'Ignored'
  } else {
    text = severity
  }

  return `<span class="severity-label">${text}</span>`
}

export function renderRevisitationDate(rule: Vulnerability | Misconfiguration): string {
  const revisitation = rule.RevisitAt;
  const severity = rule.Severity;

  if (severity === Severity.IGNORED) {
    if (revisitation !== 'never') {
      return `<span class="severity-revisitation">(until ${revisitation})</span>`
    }
  }

  return ''
}

export function escapeHTML(str: string): string {
  if (!str) {
    return str
  }

  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag]) || tag)
}

export function urlLabel(urlString: string): string {
  const url = new URL(urlString)

  const hostname = url.hostname

  if (hostname === 'github.com') {
    const repoName = url.pathname.split('/')[1]
    return `${hostname}/${repoName}`
  }

  return hostname
}

export function showLink(urlString: string) {
  const hostnamesToExclude = ["lists.apache.org"]

  const url = new URL(urlString)
  const hostname = url.hostname

  return !hostnamesToExclude.includes(hostname);
}