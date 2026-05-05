import Foundation

enum Executor {
    // SINK — Process().launch · swift.cmdi.process_launch · CWE-78
    static func execute(_ cmd: String) -> String {
        let proc = Process()
        proc.launchPath = "/bin/sh"
        proc.arguments = ["-c", cmd]
        proc.launch()
        return cmd
    }

    static func cleanTwin() -> String {
        // NEGATIVE — same sink kind with a constant argument must not report.
        let proc = Process()
        proc.launchPath = "/bin/sh"
        proc.arguments = ["-c", "echo clean"]
        proc.launch()
        return "clean"
    }
}
