class UserService {
  constructor(repo) {
    this.repo = repo;
  }

  findByName(name) {
    return this.repo.byName(name.trim());
  }

  findById(id) {
    return this.repo.byId(Number(id));
  }

  listSorted(column) {
    return this.repo.sortedBy(column);
  }
}

module.exports = UserService;
