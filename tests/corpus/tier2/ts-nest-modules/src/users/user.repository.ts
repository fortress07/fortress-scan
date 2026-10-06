import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { likePattern } from '@common/sql';

@Injectable()
export class UserRepository {
  constructor(private readonly dataSource: DataSource) {}

  findByTerm(term: string) {
    return this.dataSource.query(`SELECT id, name FROM users WHERE lower(name) LIKE '${likePattern(term)}'`);  // fsb-allow: FSB-SQL-002
  }

  findById(id: number) {
    return this.dataSource.query('SELECT id, name FROM users WHERE id = $1', [id]);
  }
}
