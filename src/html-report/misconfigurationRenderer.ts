import {Misconfiguration, TrivyResult} from "../types";
import {escapeHTML, renderRevisitationDate, renderSeverity} from "./html-utils";

export function renderMisconfigurations(result: TrivyResult) {
  if (result.Misconfigurations.length == 0) {
    return "<!-- No Misconfigurations -->"
  } else {
    return `
        <tr class="sub-header">
          <th>Misconf ID</th>
          <th>Check</th>
          <th>Severity</th>
          <th>Message</th>
        </tr>
        ${result.Misconfigurations.map(renderMisconfigurationRow).join('')}
`
  }
}

function renderMisconfigurationRow(misconfiguration: Misconfiguration) {
  return `
              <tr class="severity-${misconfiguration.Severity} ${misconfiguration.IgnoreReason ? 'multirow-first' : ''}">
                <td>
                ${misconfiguration.PrimaryURL ? `
                    <a href="${misconfiguration.PrimaryURL}" target="_blank">${escapeHTML(misconfiguration.ID)}</a>
                ` : `
                    ${escapeHTML(misconfiguration.ID)}
                `}
                </td>
                <td class="misconf-check">${escapeHTML(misconfiguration.Title)}</td>
                <td class="severity">
                  ${renderSeverity(misconfiguration)}
                  ${renderRevisitationDate(misconfiguration)}
                </td>
                <td class="message" style="white-space:normal;"">${escapeHTML(misconfiguration.Message)}</td>
              </tr>
               ${misconfiguration.IgnoreReason ? `
              <tr class="severity-${misconfiguration.Severity} multirow-last">
                <td colspan="5" class="ignore-reason">
                  ${escapeHTML(misconfiguration.IgnoreReason)}
                </td>
              </tr>
              ` : ''}
            `
}
