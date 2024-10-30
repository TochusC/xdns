// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// sender_test.go 文件定义了对 Sender 的相关测试函数。

package godns

import (
	"testing"
)

var testedRandomPacket = make([]byte, 8000)

// 测试分片
func TestFragment(t *testing.T) {
	// 测试分片
	fragments, err := Fragment(testedRandomPacket, 1500, 14)
	if err != nil {
		t.Errorf("分片失败: %s", err)
	}
	t.Logf("分片数量: %d", len(fragments))
}
