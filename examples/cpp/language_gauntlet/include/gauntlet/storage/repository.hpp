#ifndef LANGUAGE_GAUNTLET_REPOSITORY_HPP
#define LANGUAGE_GAUNTLET_REPOSITORY_HPP

#include <memory>

#include "gauntlet/model/envelope.hpp"

namespace gauntlet {

class BaseRepository {
public:
    explicit BaseRepository(Envelope data);
    virtual ~BaseRepository() = default;
    const std::string& cmd() const;
    virtual int dispatch() = 0;

protected:
    Envelope data_;
};

class Repository : public BaseRepository {
public:
    explicit Repository(Envelope data);
    int dispatch() override;
};

class AuditedRepository : public Repository {
public:
    explicit AuditedRepository(Envelope data);
    int dispatch() override;
};

int persist(Envelope env, std::string command);

}  // namespace gauntlet

#endif
