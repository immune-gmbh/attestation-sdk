package helpers

import (
	"bytes"
	"fmt"
	"io"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"

	"github.com/ulikunitz/xz"
)

// Decompress decompresses image in accordance with compression algorithm
func Decompress(b []byte, compressionType afas.CompressionType) ([]byte, error) {
	switch compressionType {
	case afas.CompressionType_None:
		return b, nil
	case afas.CompressionType_XZ:
		r, err := xz.ReaderConfig{SingleStream: true}.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("unable to create XZ reader: %w", err)
		}
		var decompressed bytes.Buffer
		_, err = io.Copy(&decompressed, r)
		if err != nil {
			return nil, fmt.Errorf("unable to decompress XZ data: %w", err)
		}
		return decompressed.Bytes(), nil
	default:
		return nil, fmt.Errorf("unknown compression type: %s", compressionType)
	}
}
