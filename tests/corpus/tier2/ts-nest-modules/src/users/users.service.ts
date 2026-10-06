import { Injectable } from '@nestjs/common';
import { UserRepository } from './user.repository';

@Injectable()
export class UsersService {
  constructor(private readonly repo: UserRepository) {}

  search(term: string) {
    return this.repo.findByTerm(term.toLowerCase());
  }

  byId(id: number) {
    return this.repo.findById(id);
  }
}
