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
