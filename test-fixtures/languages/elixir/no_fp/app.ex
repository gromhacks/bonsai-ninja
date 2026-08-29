defmodule App do
  @const_ok "ls /tmp"
  def decoy do
    _unused = System.get_env("IGNORED")
    System.cmd("sh", ["-c", @const_ok])
  end
  def unrelated_chain do
    String.upcase("hello")
  end
end
