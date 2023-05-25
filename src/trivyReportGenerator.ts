#!/usr/bin/env node
import yargs from 'yargs/yargs';
import {hideBin} from 'yargs/helpers';
import * as fs from 'fs';
import {renderHtmlReport} from "./html-report/trivyHtmlRenderer";
import {parseReport} from "./reportParser";
import {trivyResultValidator} from "./trivyResultValidator";
import {reportRedundantIgnore, reportUnusedIgnores} from "./ignoreFileValidator";

function generateReport(reportFilePath: string, resultFilePath: string, ignoreFilePath: string) {
  const results = parseReport(reportFilePath, ignoreFilePath)
  renderHtmlReport(results, resultFilePath);
}

function checkResult(reportFilePath: string, ignoreFilePath: string) {
  const results = parseReport(reportFilePath, ignoreFilePath)
  trivyResultValidator(results)
}

yargs(hideBin(process.argv))
    .command('generate-report', 'generates an html report', (yargs) => {
      return yargs
          .option('report-file', {
            type: 'string',
            alias: 'r',
            description: 'The report-file generated by trivy (JSON)',
            demandOption: true
          })
          .option('ignore-file', {
            type: 'string',
            description: 'The ignore-file',
            demandOption: true
          })
          .option('result-file', {
            type: 'string',
            description: 'An HTML report that takes the provided ignore file into account',
            demandOption: true
          })
          .check(argv => {
            if (!fs.existsSync(argv.reportFile as string)) {
              throw new Error(`The report-file at ${argv.reportFile} does not exist`);
            }
            if (!fs.existsSync(argv.ignoreFile as string)) {
              throw new Error(`The ignore-file at ${argv.ignoreFile} does not exist`);
            }

            try {
              JSON.parse(fs.readFileSync(argv.ignoreFile as string).toString())
            } catch (e) {
              throw new Error(`The ignore-file ${argv.ignoreFile} is not a valid json file`);
            }

            return true
          })
    }, (argv) => {
      reportRedundantIgnore(argv.ignoreFile)
      generateReport(argv.reportFile, argv.resultFile, argv.ignoreFile);
    })
    .command('check-result', 'validates, that the trivy report file does not contain any unignored CVE/Misconfiguration', (yargs) => {
      return yargs
          .option('report-file', {
            type: 'string',
            description: 'All original trivy report-files (JSON)',
            demandOption: true
          })
          .option('ignore-file', {
            type: 'string',
            description: 'The ignore-file',
            demandOption: true
          })
          .check(argv => {
            if (!fs.existsSync(argv.reportFile as string)) {
              throw new Error(`The report-file at ${argv.reportFile} does not exist`)
            }
            if (!fs.existsSync(argv.ignoreFile as string)) {
              throw new Error(`The ignore-file at ${argv.ignoreFile} does not exist`)
            }
            return true
          })
    }, (argv) => {
      console.info(`Validating that there are no unhandled vulnerabilities in '${argv.reportFile}'.`)
      reportRedundantIgnore(argv.ignoreFile)
      checkResult(argv.reportFile, argv.ignoreFile)
    })
    .command('validate-ignore-rules', 'validates that all rules in the ignore file are actually ignoring a reported vulnerability/misconfiguration.', (yargs) => {
      return yargs
          .option('trivy-report-directory', {
            type: 'string',
            description: 'The directory containing all trivy report-files (JSON)',
            demandOption: true
          })
          .option('ignore-file', {
            type: 'string',
            description: 'The ignore-file',
            demandOption: true
          })
          .check(argv => {
            if (!fs.existsSync(argv.trivyReportDirectory as string)) {
              throw new Error(`The trivy-report-directory at ${argv.trivyReportDirectory} does not exist`);
            }
            if (!fs.existsSync(argv.ignoreFile as string)) {
              throw new Error(`The ignore-file at ${argv.ignoreFile} does not exist`)
            }
            return true
          })
    }, (argv) => {
      console.info(`Validating that there are no unused ignores in '${argv.ignoreFile}'.`)
      reportUnusedIgnores(argv.ignoreFile, argv.trivyReportDirectory)
      console.info(`No unused ignores found in '${argv.ignoreFile}'.`)
    })
    .demandCommand()
    .parse()
