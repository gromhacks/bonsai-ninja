// Class hierarchy — abstract base, virtual methods, smart pointers,
// override + base-call — all preserving taint on the way to the sink.
#include <memory>
#include <string>
#include <utility>

#include "envelope.hpp"

int execute(const std::string& cmd);

// Abstract base — virtual run() dispatched via vtable.
class BaseRepository {
public:
    explicit BaseRepository(Envelope data) : data_(std::move(data)) {}
    virtual ~BaseRepository() = default;

    // Accessor exposes the tainted cmd field.
    const std::string& cmd() const { return data_.cmd; }

    virtual int dispatch() = 0;

protected:
    Envelope data_;
};

class Repository : public BaseRepository {
public:
    explicit Repository(Envelope data) : BaseRepository(std::move(data)) {}

    int dispatch() override {
        const std::string& c = cmd();
        return execute(c);
    }
};

class AuditedRepository : public Repository {
public:
    explicit AuditedRepository(Envelope data) : Repository(std::move(data)) {}

    int dispatch() override {
        // Base-call preserves taint across the inheritance chain.
        return Repository::dispatch();
    }
};

int run(Envelope env) {
    AuditedRepository repo(std::move(env));
    const std::string& c = repo.cmd();
    return execute(c);
}

int persist(Envelope env) {
    std::unique_ptr<BaseRepository> repo = std::make_unique<AuditedRepository>(std::move(env));
    (void)repo;
    return run(std::move(env));
}
