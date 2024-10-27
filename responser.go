package godns

type Responser interface {
	Response(qInfo QueryInfo) (ResponseInfo, error)
}

// DullResponser 是一个笨笨的 Responser 实现。
type DullResponser struct{}

func (d DullResponser) Response(qInfo QueryInfo) (ResponseInfo, error) {
	return ResponseInfo{}, nil
}
