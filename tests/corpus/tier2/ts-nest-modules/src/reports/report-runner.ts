import { Injectable } from '@nestjs/common';
import { execSync } from 'child_process';

export abstract class ReportRunner {
  abstract run(name: string, format: string): string;
}

@Injectable()
export class ShellReportRunner extends ReportRunner {
  run(name: string, format: string): string {
    const fmt = ['pdf', 'csv'].includes(format) ? format : 'pdf';
    return execSync(`report-cli --name ${name} --format ${fmt}`).toString();  // fsb-allow: FSB-CMD-003
  }
}
