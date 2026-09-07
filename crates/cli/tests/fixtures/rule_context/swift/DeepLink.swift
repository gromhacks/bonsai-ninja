import Foundation
import SwiftUI
import WebKit
struct ReviewView: View {
    let webView: WKWebView
    var body: some View {
        Text("Review").onOpenURL { url in
            webView.loadHTMLString(url.absoluteString.removingPercentEncoding!, baseURL: nil)
        }
    }
}
func localControl(webView: WKWebView) {
    let input = readLine()!
    webView.loadHTMLString(input, baseURL: nil)
}
