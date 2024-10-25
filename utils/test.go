// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// test.go 文件定义了测试用的一些常用函数和类型。
package utils

import (
	"fmt"
)

// FailedResult 表示测试失败的原因。
type FailedResult int

// 测试失败类型。
const (
	ResultMismatch FailedResult = iota
	ErrorMismatch
)

// String 返回 FailedResult 的字符串表示。
func (f FailedResult) String() string {
	switch f {
	case ResultMismatch:
		return "Result Mismatch!"
	case ErrorMismatch:
		return "Error Mismatch!"
	default:
		return fmt.Sprintf("Unknown FailedResult!: %d", f)
	}
}
