defmodule ReviewController do
  use Web, :controller
  def encoded(conn, params) do
    Phoenix.Controller.redirect(conn, external: URI.encode(params["next"]))
  end
  def direct(conn, params) do
    Phoenix.Controller.redirect(conn, external: params["next"])
  end
end
