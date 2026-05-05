# Class hierarchy — inheritance, mix-in modules, attr accessors,
# singleton/class methods — all preserving taint on the way to the sink.
require_relative 'executor'

module Auditable
  def audit!; self; end
end

class Repository
  include Auditable

  attr_reader :data

  def initialize(data)
    @data = data
  end

  # Getter propagates taint out of the instance variable.
  def cmd
    @data[:cmd]
  end

  def self.wrap(data)
    new(data)
  end

  def run
    audit!
    Executor.execute(cmd)
  end
end

class AuditedRepository < Repository
  def run
    # super preserves taint across the inheritance chain.
    super
  end
end

module Storage
  def self.persist(envelope)
    repo = AuditedRepository.wrap(envelope)
    repo.run
  end
end
