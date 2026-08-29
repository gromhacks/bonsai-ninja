package main

func RunPipeline(payload string) {
	wrapped := "[" + payload + "]"
	TransformAndForward(wrapped)
}
