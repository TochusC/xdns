package godns

type Responser interface {
	Response(qInfo QueryInfo) (ResponseInfo, error)
}

// DullResponser 是一个"笨笨的" Responser 实现。
// 它不会对 DNS 请求做出任何回复。
type DullResponser struct{}

func (d DullResponser) Response(qInfo QueryInfo) (ResponseInfo, error) {
	return ResponseInfo{}, nil
}
