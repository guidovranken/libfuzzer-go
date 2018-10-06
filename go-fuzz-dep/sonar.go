// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package gofuzzdep

/*
#cgo CFLAGS: -std=c99

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef int memcmp_cb_t(void*, const void*, const void*, size_t n);

static void callMemcmpCB(void* CBPtr, size_t ID, unsigned char* data1, size_t size1, unsigned char* data2, size_t size2)
{
	if ( CBPtr == NULL ) {
	    return;
	}
	memcmp_cb_t* CB = (memcmp_cb_t*)CBPtr;
	const size_t minsize = size1 < size2 ? size1 : size2;
	CB((void*)ID, data1, data2, minsize);
}

*/
import "C"

import (
	"unsafe"

	. "go-fuzz-defs"
)

const failure = ^uint8(0)

type iface struct {
	typ unsafe.Pointer
	val unsafe.Pointer
}

var memcmpCB unsafe.Pointer

func SetMemcmpCBPtr(ptr unsafe.Pointer) {
	memcmpCB = ptr
}

func Sonar(v1, v2 interface{}, id uint32) {
	var serialized1 [2*SonarMaxLen]byte
	var serialized2 [2*SonarMaxLen]byte
	n1, _ := serialize(v1, v2, serialized1[:])
	if n1 == failure {
		return
	}
	s1 := serialized1[:n1]

	n2, _ := serialize(v2, v1, serialized2[:])
	if n2 == failure {
		return
	}
	s2 := serialized2[:n2]

	if len(s1) == 0 || len(s2) == 0 {
	    return
	}
	C.callMemcmpCB(
	    memcmpCB,
	    C.ulong(id),
	    (*C.uchar)(unsafe.Pointer(&s1[0])), C.ulong(len(s1)),
	    (*C.uchar)(unsafe.Pointer(&s2[0])), C.ulong(len(s2)))
}

func serialize(v, v2 interface{}, buf []byte) (n, flags uint8) {
	switch vv := v.(type) {
	case int8:
		buf[0] = byte(vv)
		return 1, SonarSigned
	case uint8:
		buf[0] = byte(vv)
		return 1, 0
	case int16:
		return serialize16(buf, uint16(vv)), SonarSigned
	case uint16:
		return serialize16(buf, vv), 0
	case int32:
		return serialize32(buf, uint32(vv)), SonarSigned
	case uint32:
		return serialize32(buf, vv), 0
	case int64:
		return serialize64(buf, uint64(vv)), SonarSigned
	case uint64:
		return serialize64(buf, vv), 0
	case int:
		if unsafe.Sizeof(vv) == 4 {
			return serialize32(buf, uint32(vv)), SonarSigned
		} else {
			return serialize64(buf, uint64(vv)), SonarSigned
		}
	case uint:
		if unsafe.Sizeof(vv) == 4 {
			return serialize32(buf, uint32(vv)), 0
		} else {
			return serialize64(buf, uint64(vv)), 0
		}
	case string:
		if len(vv) > SonarMaxLen {
			return failure, 0
		}
		return uint8(copy(buf, vv)), SonarString
	case [1]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [2]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [3]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [4]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [5]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [6]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [7]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [8]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [9]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [10]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [11]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [12]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [13]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [14]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [15]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [16]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [17]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [18]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [19]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [20]byte:
		return uint8(copy(buf, vv[:])), SonarString
	default:
		// Special case: string literal is compared with a variable of
		// user type with string underlying type:
		//	type Name string
		//	var name Name
		//	if name == "foo" { ... }
		if _, ok := v2.(string); ok {
			s := *(*string)((*iface)(unsafe.Pointer(&v)).val)
			if len(s) <= SonarMaxLen {
				return uint8(copy(buf[:], s)), SonarString
			}
		}
		return failure, 0
	}
}

func serialize16(buf []byte, v uint16) uint8 {
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	return 2
}

func serialize32(buf []byte, v uint32) uint8 {
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	return 4
}

func serialize64(buf []byte, v uint64) uint8 {
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	return 8
}

func deserialize64(buf []byte) uint64 {
	return uint64(buf[0])<<0 |
		uint64(buf[1])<<8 |
		uint64(buf[2])<<16 |
		uint64(buf[3])<<24 |
		uint64(buf[4])<<32 |
		uint64(buf[5])<<40 |
		uint64(buf[6])<<48 |
		uint64(buf[7])<<56
}
