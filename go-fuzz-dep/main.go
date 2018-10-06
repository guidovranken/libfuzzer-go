// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package gofuzzdep

import (
	"unsafe"

	. "go-fuzz-defs"
)

var (
	CoverTab    *[CoverSize]byte
	CoverTabTmp [CoverSize]byte
)


func init() {
	CoverTab = (*[CoverSize]byte)(unsafe.Pointer(&CoverTabTmp[0]))
}

func Initialize(coverTabPtr unsafe.Pointer, coverTabSize uint64) {
	if coverTabSize != CoverSize {
	    panic("Incorrect cover tab size")
	}
	CoverTab = (*[CoverSize]byte)(coverTabPtr)
}

func Main(f func([]byte) int) {
}
