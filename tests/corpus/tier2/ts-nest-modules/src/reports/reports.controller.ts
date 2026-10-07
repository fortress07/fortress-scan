import { Body, Controller, Get, Post, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { escapeHtml } from '../common';
import { ReportRunner } from './report-runner';

interface GenerateDto {
  name: string;
  format: string;
}

@Controller('reports')
export class ReportsController {
  constructor(private readonly runner: ReportRunner) {}

  @Post('generate')
  generate(@Body() body: GenerateDto) {
    return this.runner.run(body.name, body.format); // fsb-expect: FSB-CMD-001
  }

  @Get('title')
  title(@Query('t') t: string, @Res() res: Response) {
    res.send('<h1>' + escapeHtml(t) + '</h1>');
  }

  @Get('raw-title')
  rawTitle(@Query('t') t: string, @Res() res: Response) {
    res.send('<h1>' + t + '</h1>'); // fsb-expect: FSB-XSS-001
  }
}
