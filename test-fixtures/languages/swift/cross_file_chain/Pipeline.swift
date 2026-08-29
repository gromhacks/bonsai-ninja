import Foundation

func runPipeline(payload: String) {
    let wrapped = "[\(payload)]"
    transformAndForward(value: wrapped)
}
