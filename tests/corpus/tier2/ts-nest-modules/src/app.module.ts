import { Module } from '@nestjs/common';
import { UsersController } from './users/users.controller';
import { UsersService } from './users/users.service';
import { UserRepository } from './users/user.repository';
import { ReportsController } from './reports/reports.controller';
import { ReportRunner, ShellReportRunner } from './reports/report-runner';
import { AdminController } from './admin/admin.controller';

@Module({
  controllers: [UsersController, ReportsController, AdminController],
  providers: [UsersService, UserRepository, { provide: ReportRunner, useClass: ShellReportRunner }],
})
export class AppModule {}
