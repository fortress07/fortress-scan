import { Controller, Get, Query } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { likePattern } from '@common/sql';

@Controller('admin')
export class AdminController {
  constructor(private readonly ds: DataSource) {}

  @Get('audit')
  audit(@Query('user') user: string) {
    return this.ds.query("SELECT * FROM audit WHERE actor LIKE '" + likePattern(user) + "'"); // fsb-expect: FSB-SQL-001
  }

  @Get('audit-safe')
  auditSafe(@Query('user') user: string) {
    return this.ds.query('SELECT * FROM audit WHERE actor LIKE $1', [likePattern(user)]);
  }
}
