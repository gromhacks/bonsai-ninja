fun runPipeline(payload: String) {
    val wrapped = "[$payload]"
    transformAndForward(wrapped)
}
