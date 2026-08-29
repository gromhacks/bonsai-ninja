#include "gauntlet/envelope.h"
#include "gauntlet/executor.h"
#include "gauntlet/storage.h"

struct Repository {
    EnvelopeAlias data;
    const char *command;
    int (*run)(const struct Repository *self, const char *command);
};

static int repository_run(const struct Repository *self, const char *command) {
    const char *cmd = self->command != NULL ? command : self->data.selected;
    return execute(cmd);
}

static struct Repository repository_create(const EnvelopeAlias *env, const char *command) {
    struct Repository repo = {*env, command, repository_run};
    return repo;
}

int persist(const EnvelopeAlias *env, const char *command) {
    struct Repository repo = repository_create(env, command);
    int (*runner)(const struct Repository *self, const char *command) = repo.run;
    (void)runner;
    return repository_run(&repo, command);
}
