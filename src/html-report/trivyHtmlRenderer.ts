import {TrivyResult} from "../types";
import * as fs from 'fs';
import {renderVulnerabilities} from "./vulnerabilityRenderer";
import {renderMisconfigurations} from "./misconfigurationRenderer";
import {escapeHTML} from "./html-utils";

export function renderHtmlReport(trivyResults: TrivyResult[], resultFilePath: string) {
  const t = new Date()
  const timeString = `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())} ${pad(t.getHours())}:${pad(t.getMinutes())}:${pad(t.getSeconds())}`
  const css = fs.readFileSync(`${__dirname}/../../assets/style.css`)

  const tpl: string = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      ${css}
    </style>
    <title>Trivy Report - ${timeString}</title>
  </head>
  <body>
    <div>
      <h1>Trivy Report - ${timeString}</h1>
      <!--div class="info">
        <ul>
          <li><span class="info-label">Generated at:</span><span class="info-value">${timeString}</span></li>
        </ul>
      </div-->
        ${trivyResults.map(result => `
          <table>
                  <tr class="group-header"><th colspan="6">${escapeHTML(result.Type)} (${escapeHTML(result.Target)})</th></tr>
                  ${renderVulnerabilities(result)}
                  ${renderMisconfigurations(result)} 
          </table>
        `).join('')}
    </div>
  </body>
</html>
`
  fs.writeFileSync(resultFilePath, tpl)
}

const pad = (num: number) => String(num).padStart(2, '0')