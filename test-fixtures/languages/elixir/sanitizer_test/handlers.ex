# Elixir sanitizer-fixture — parallel handlers per sink family. Safe
# variants keep the tainted value flowing all the way to the sink
# (with the sanitizer wrapping it in between) so the engine attaches
# sanitizer evidence to the finding.
defmodule SanitizerTest.Handlers do
  # --- Command injection -------------------------------------------------

  def cmd_raw(input) do
    :os.cmd(String.to_charlist("ping " <> input))
  end

  def cmd_safe(input) do
    # Route the tainted input through a URL-encode first, then still
    # reach the :os.cmd sink — the sanitizer attaches as evidence on
    # the finding rather than blocking it.
    safe = URI.encode_www_form(input)
    :os.cmd(String.to_charlist("ping " <> safe))
  end

  # --- XSS (Phoenix response) -------------------------------------------

  def xss_raw(conn, name) do
    Plug.Conn.send_resp(conn, 200, "<p>Hello, #{name}</p>")
  end

  def xss_safe(conn, name) do
    safe = Phoenix.HTML.html_escape(name)
    Plug.Conn.send_resp(conn, 200, "<p>Hello, #{safe}</p>")
  end

  # --- Open redirect (shell-injection sink; redirect sanitizer) ---------

  def redirect_raw(target) do
    :os.cmd(String.to_charlist("curl -L " <> target))
  end

  def redirect_safe(target) do
    safe = URI.encode_www_form(target)
    :os.cmd(String.to_charlist("curl -L " <> safe))
  end

  # --- Timing attack (raw equality vs constant-time compare) ------------

  def token_eq_raw(given, expected), do: given == expected

  def token_eq_safe(given, expected) do
    Plug.Crypto.secure_compare(given, expected)
  end
end
