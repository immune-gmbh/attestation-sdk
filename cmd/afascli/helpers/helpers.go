package helpers

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// ParseTPMEventlog tries to path TPM eventlog located in provided path
func ParseTPMEventlog(eventLogPath string) (*tpmeventlog.TPMEventLog, error) {
	eventLogFile, err := os.Open(eventLogPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open EventLog '%s': %w", eventLogPath, err)
	}

	eventLog, err := tpmeventlog.Parse(eventLogFile)
	if err != nil {
		return nil, fmt.Errorf("unable to parse EventLog '%s': %w", eventLogPath, err)
	}
	return eventLog, nil
}

// ConvertUserInputPCR tries to convert user-provided PCR hash value into a sequence of bytes
func ConvertUserInputPCR(pcr0SHA string) ([]byte, error) {
	switch len(pcr0SHA) {
	case 0:
		// no value
		return nil, nil
	case sha1.Size, sha256.Size:
		// raw binary value
		return []byte(pcr0SHA), nil

	// TODO: drop it?
	case 29:
		// base64-encoded value
		expectedPCR0SHA1, err := base64.StdEncoding.DecodeString(pcr0SHA)
		if err != nil {
			return nil, fmt.Errorf("unable to parse string '%s' as base64 encoded data: %w", pcr0SHA, err)
		}
		return expectedPCR0SHA1, nil
	}

	// assume hex encoding with optional "0x" prefix
	str := strings.TrimPrefix(pcr0SHA, "0x")
	if len(str) == 2*sha1.Size || len(str) == 2*sha256.Size {
		expectedPCR0, err := hex.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("unable to parse string '%s' as hex: %w", str, err)
		}
		return expectedPCR0, nil
	}
	return nil, fmt.Errorf("unable to determine encoding type of PCR0 value '%s' (len:%d), try hex-encoded or base64-encoded value instead, expected length is 40 (sha1), 64 (sha256) or 29 characters", pcr0SHA, len(pcr0SHA))
}

// ParseRegisters parses status register given the path.
func ParseRegisters(registersPath string) (registers.Registers, error) {
	if registersPath == "" {
		return nil, nil
	}

	registersJSON, err := ioutil.ReadFile(registersPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read registers: %w", err)
	}

	result := registers.Registers{}
	if err := result.UnmarshalJSON(registersJSON); err != nil {
		return nil, fmt.Errorf("unable to unmarshal registers: %w", err)
	}

	return result, nil
}

// DeserialiseThrift deserializes a Thrift structure from its binary form.
func DeserialiseThrift(bytes []byte, out thrift.Struct) error {

	deserializer := thrift.NewDeserializer()
	factory := thrift.NewCompactProtocolFactory()
	deserializer.Protocol = factory.GetProtocol(deserializer.Transport)

	err := deserializer.Read(out, bytes)
	if err != nil {
		return fmt.Errorf("unable to deserialise bytes into object: %v", err)
	}

	return nil
}

// SerialiseThrift serializes a Thrift structure into its binary form.
func SerialiseThrift(in thrift.Struct) ([]byte, error) {

	serializer := thrift.NewSerializer()
	factory := thrift.NewCompactProtocolFactory()
	serializer.Protocol = factory.GetProtocol(serializer.Transport)

	bytes, err := serializer.Write(in)
	if err != nil {
		return nil, fmt.Errorf("unable to serialise object into bytes: %v", err)
	}

	return bytes, nil

}
