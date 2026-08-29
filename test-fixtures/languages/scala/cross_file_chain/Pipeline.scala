object Pipeline {
  def runPipeline(payload: String): Unit = {
    val wrapped = "[" + payload + "]"
    Transformer.transformAndForward(wrapped)
  }
}
