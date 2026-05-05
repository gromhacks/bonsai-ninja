module Executor
  # SINK — Kernel#system · ruby.cmdi.kernel_system · CWE-78
  def self.execute(cmd)
    system(cmd)
    cmd
  end

  def self.clean_twin
    # NEGATIVE — same sink kind with a constant argument must not report.
    system('echo clean')
    'clean'
  end
end
