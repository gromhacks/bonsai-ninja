require 'action_controller'
require 'shellwords'
class ReviewController < ActionController::Base
  def quoted
    exec(Shellwords.escape(params[:exe]))
  end
  def direct
    exec(params[:exe])
  end
end
