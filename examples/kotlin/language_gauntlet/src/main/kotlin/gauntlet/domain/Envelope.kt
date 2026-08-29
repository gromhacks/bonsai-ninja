package gauntlet.domain

enum class Kind { RUN, EVAL }

data class Envelope(
    val kind: Kind,
    val cmd: String,
    val user: String,
    val length: Int,
    val extras: List<String>,
)
