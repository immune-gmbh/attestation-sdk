// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package objhash

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"math"
	"reflect"
	"unsafe"

	"github.com/xaionaro-go/unsafetools"
	"lukechampine.com/blake3"
)

const blake3Size = 64 // 512 bits

// Builder is the handler which converts a set of variables to a ObjHash.
type Builder struct {
	Blake3 *blake3.Hasher
	SHA512 hash.Hash
}

// NewBuilder returns a new instance of Builder.
func NewBuilder() *Builder {
	return &Builder{
		Blake3: blake3.New(blake3Size, nil),
		SHA512: sha512.New(),
	}
}

// Custom allows to customize extending values into cache key
type Custom interface {
	CacheWrite(b *Builder) error
}

func extend(h hash.Hash, in []byte) error {
	oldHash := h.Sum(nil)
	_, err := h.Write(oldHash)
	if err != nil {
		return fmt.Errorf("unable to extend %T (step 0): %w", h, err)
	}
	_, err = h.Write(in)
	if err != nil {
		return fmt.Errorf("unable to extend %T (step 1): %w", h, err)
	}

	return nil
}

func (b *Builder) extendBytes(in []byte) error {
	if err := extend(b.Blake3, in); err != nil {
		return fmt.Errorf("unable to extend Blake3: %w", err)
	}
	if err := extend(b.SHA512, in); err != nil {
		return fmt.Errorf("unable to extend SHA512: %w", err)
	}

	return nil
}

func (b *Builder) extendString(in string) error {
	return b.extendBytes(unsafetools.CastStringToBytes(in))
}

func (b *Builder) extendBool(v bool) error {
	if v {
		return b.extendUint8(1)
	} else {
		return b.extendUint8(0)
	}
}

func (b *Builder) extendUint8(u uint8) error {
	var in []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&in))
	hdr.Data = uintptr(unsafe.Pointer(&u))
	hdr.Len = 1
	hdr.Cap = 1
	err := b.extendBytes(in)
	return err
}

func (b *Builder) extendUint16(u uint16) error {
	var in []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&in))
	hdr.Data = uintptr(unsafe.Pointer(&u))
	hdr.Len = 2
	hdr.Cap = 2
	err := b.extendBytes(in)
	return err
}

func (b *Builder) extendUint32(u uint32) error {
	var in []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&in))
	hdr.Data = uintptr(unsafe.Pointer(&u))
	hdr.Len = 4
	hdr.Cap = 4
	err := b.extendBytes(in)
	return err
}

func (b *Builder) extendUint64(u uint64) error {
	var in []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&in))
	hdr.Data = uintptr(unsafe.Pointer(&u))
	hdr.Len = 8
	hdr.Cap = 8
	err := b.extendBytes(in)
	return err
}

func (b *Builder) extendUint(u uint) error {
	return b.extendUint64(uint64(u))
}

// Build just calls Write and Result.
func (b *Builder) Build(args ...any) (ObjHash, error) {
	if err := b.Write(args...); err != nil {
		return ObjHash{}, err
	}

	return b.Result(), nil
}

// Reset resets the set of variables.
func (b *Builder) Reset() {
	b.Blake3.Reset()
	b.SHA512.Reset()
}

// Result returns a cache key for a current set of variables.
func (b *Builder) Result() ObjHash {
	var result ObjHash
	copy(result[:], b.Blake3.Sum(nil))
	copy(result[blake3Size:], b.SHA512.Sum(nil))
	return result
}

// Write adds variables.
func (b *Builder) Write(args ...any) error {
	for idx, arg := range args {
		// discuss: I'm against soft logic, let's remove this soft type assertion
		// and always do reflect.ValueOf. Otherwise it is a hidden behavior, and
		// I find hidden behaviors in hash functions pretty dangerous.
		//
		// Let's discuss this.
		//
		//                                                      -- Dmitrii Okunev
		v, ok := arg.(reflect.Value)
		if !ok {
			v = reflect.ValueOf(arg)
		}
		err := b.write(v)
		if err != nil {
			return fmt.Errorf("unable to append argument #%d: %w", idx, err)
		}
	}

	return nil
}

func (b *Builder) write(v reflect.Value) error {
	if custom, ok := v.Interface().(Custom); ok {
		return custom.CacheWrite(b)
	}

	b.extendUint64(uint64(v.Kind()))
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			if err := b.extendBytes(v.Slice(0, v.Len()).Bytes()); err != nil {
				return fmt.Errorf("unable to write bytes: %w", err)
			}
			return nil
		}
		if err := b.extendUint(uint(v.Len())); err != nil {
			return fmt.Errorf("unable to write length: %w", err)
		}
		for i := 0; i < v.Len(); i++ {
			if err := b.write(v.Index(i)); err != nil {
				return fmt.Errorf("unable to write item %d: %w", i, err)
			}
		}
	case reflect.Uint64, reflect.Uint, reflect.Uintptr:
		if err := b.extendUint64(v.Uint()); err != nil {
			return fmt.Errorf("unable to write uint64: %w", err)
		}
	case reflect.Int64, reflect.Int:
		if err := b.extendUint64(uint64(v.Int())); err != nil {
			return fmt.Errorf("unable to write int64: %w", err)
		}
	case reflect.Uint32:
		if err := b.extendUint32(uint32(v.Uint())); err != nil {
			return fmt.Errorf("unable to write uint32: %w", err)
		}
	case reflect.Int32:
		if err := b.extendUint32(uint32(v.Int())); err != nil {
			return fmt.Errorf("unable to write int32: %w", err)
		}
	case reflect.Uint16:
		if err := b.extendUint16(uint16(v.Uint())); err != nil {
			return fmt.Errorf("unable to write uint16: %w", err)
		}
	case reflect.Int16:
		if err := b.extendUint16(uint16(v.Int())); err != nil {
			return fmt.Errorf("unable to write int16: %w", err)
		}
	case reflect.Uint8:
		if err := b.extendUint8(uint8(v.Uint())); err != nil {
			return fmt.Errorf("unable to write uint8: %w", err)
		}
	case reflect.Int8:
		if err := b.extendUint8(uint8(v.Int())); err != nil {
			return fmt.Errorf("unable to write int8: %w", err)
		}
	case reflect.Float64, reflect.Float32:
		if err := b.extendUint64(math.Float64bits(v.Float())); err != nil {
			return fmt.Errorf("unable to write int64: %w", err)
		}
	case reflect.String:
		if err := b.extendString(v.String()); err != nil {
			return fmt.Errorf("unable to write string: %w", err)
		}
	case reflect.Bool:
		if err := b.extendBool(v.Bool()); err != nil {
			return fmt.Errorf("unable to write bool: %w", err)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			fType := t.Field(i)
			isUnexported := fType.PkgPath != ""
			if isUnexported {
				continue
			}
			if fType.Tag.Get("objhash") == "skip" {
				continue
			}
			f := v.Field(i)
			if err := b.write(f); err != nil {
				return fmt.Errorf("unable to write field #%d '%s': %w", i, fType.Name, err)
			}
		}
	case reflect.Ptr:
		if err := b.extendBool(v.IsNil()); err != nil {
			return fmt.Errorf("unable to write if the pointer is nil: %w", err)
		}
		if v.IsNil() {
			return nil
		}
		if err := b.write(v.Elem()); err != nil {
			return fmt.Errorf("unable to write dereferenced value: %w", err)
		}
	case reflect.Interface:
		unwrapped := reflect.ValueOf(v.Interface()) // unwrap the interface
		if err := b.extendBool(unwrapped.IsValid()); err != nil {
			return fmt.Errorf("unable to write if the interface value is valid: %w", err)
		}
		if !unwrapped.IsValid() {
			return nil
		}
		if err := b.write(unwrapped); err != nil {
			return fmt.Errorf("unable to write the unwrapped value: %w", err)
		}
	default:
		return fmt.Errorf("unknown kind: %v", v.Kind())
	}

	return nil
}
