# Production Rails controller. The root app.rb is only the launcher; the remote
# boundary remains in the application tree selected by the production profile.
require_relative '../../lib/application/pipeline'

class CommandsController < ActionController::Base
  def handle_request
    # SOURCE — Rails params are remote HTTP input.
    raw = params
    user = 'remote'

    envelope = {
      kind: :run,
      cmd: "#{raw}",
      user: user,
      length: raw&.length || 0,
      extras: [raw.dup],
    }

    Pipeline.orchestrate(envelope)
  end
end
