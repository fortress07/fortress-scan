import { Controller, Get, Param, Query } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get('search')
  search(@Query('q') q: string) {
    return this.users.search(q); // fsb-expect: FSB-SQL-001
  }

  @Get(':id')
  byId(@Param('id') id: string) {
    return this.users.byId(parseInt(id, 10));
  }
}
