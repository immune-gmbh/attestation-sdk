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

package analysis

// Blob is an interface of a huge blob. Semantically in this package
// it is just `[]byte`. But:
//  1. Sometimes the consumers of this package
//     may have constraints against passing large blobs directly as input.
//     For example if we want analysis be storable and reproducible, in some infras
//     it will store only an object ID in the input instead of the whole blob
//     (and object itself will be stored in an object storage, like GitHub LFS or BlobStorage).
//  2. Another reason to pass objectIDs instead of images themselves is to make cache
//     more efficient, because calculated hashes for large objects might be too expensive.
//
// WARNING! The object, implementing this interface should export enough data to uniquely
// identify the specific image. Internally package `analysis` hashes all the input to
// calculate the cache key. So if two different images exports exactly the same fields,
// then there will be INVALID DATA provided by the cache.
type Blob interface {
	Bytes() []byte
}

// BytesBlob is a simple implementation of a Blob, based on a simple []byte.
type BytesBlob []byte

// Bytes implements Blob.
func (s BytesBlob) Bytes() []byte {
	return s
}
