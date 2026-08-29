#include <memory>
#include <utility>

#include "gauntlet/runtime/executor.hpp"
#include "gauntlet/storage/repository.hpp"

namespace gauntlet {

BaseRepository::BaseRepository(Envelope data) : data_(std::move(data)) {}

const std::string& BaseRepository::cmd() const {
    return data_.cmd;
}

Repository::Repository(Envelope data) : BaseRepository(std::move(data)) {}

int Repository::dispatch() {
    const std::string& value = cmd();
    return execute(value);
}

AuditedRepository::AuditedRepository(Envelope data) : Repository(std::move(data)) {}

int AuditedRepository::dispatch() {
    return Repository::dispatch();
}

struct RepositoryState {
    std::string command;
};

static int run_repository(const RepositoryState& repository) {
    return execute(repository.command);
}

int persist(Envelope env, std::string command) {
    AuditedRepository inheritance_probe(std::move(env));
    (void)inheritance_probe;
    std::unique_ptr<BaseRepository> ownership_probe;
    (void)ownership_probe;
    RepositoryState repository{std::move(command)};
    return run_repository(repository);
}

}  // namespace gauntlet
