object Transformer {
  def transformAndForward(value: String): Unit = {
    val upper = value.toUpperCase
    Executor.execute(upper)
  }
}
