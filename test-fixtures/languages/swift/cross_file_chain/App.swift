// Cross-file argument flow audit fixture (Swift).
import Foundation

func handler() {
    // POSITIVE
    let user = readLine() ?? ""
    runPipeline(payload: user)
}

func handlerSplit() {
    // POSITIVE
    let user = readLine() ?? ""
    let flag = readLine() ?? ""
    runPipeline(payload: "\(user):\(flag)")
}
