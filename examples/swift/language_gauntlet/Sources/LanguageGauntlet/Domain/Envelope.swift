public enum Kind {
    case run
    case eval
}

public struct Envelope {
    public var kind: Kind
    public var cmd: String
    public var user: String
    public var length: Int
    public var extras: [String]

    public init(kind: Kind, cmd: String, user: String, length: Int, extras: [String]) {
        self.kind = kind
        self.cmd = cmd
        self.user = user
        self.length = length
        self.extras = extras
    }
}
