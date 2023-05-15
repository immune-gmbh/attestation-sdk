// Code generated by Thrift Compiler (0.14.0). DO NOT EDIT.

package biosrtmanalysis

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/apache/thrift/lib/go/thrift"
	"time"
)

// (needed to ensure safety because of naive import list construction.)
var _ = thrift.ZERO
var _ = fmt.Printf
var _ = context.Background
var _ = time.Now
var _ = bytes.Equal

type Validation int64

const (
	Validation_Unknown              Validation = 0
	Validation_CorrectSignature     Validation = 1
	Validation_RTMVolumeNotFound    Validation = 2
	Validation_RTMSignatureNotFound Validation = 3
	Validation_PSBDisabled          Validation = 5
	Validation_InvalidFormat        Validation = 6
	Validation_IncorrectSignature   Validation = 7
)

func (p Validation) String() string {
	switch p {
	case Validation_Unknown:
		return "Unknown"
	case Validation_CorrectSignature:
		return "CorrectSignature"
	case Validation_RTMVolumeNotFound:
		return "RTMVolumeNotFound"
	case Validation_RTMSignatureNotFound:
		return "RTMSignatureNotFound"
	case Validation_PSBDisabled:
		return "PSBDisabled"
	case Validation_InvalidFormat:
		return "InvalidFormat"
	case Validation_IncorrectSignature:
		return "IncorrectSignature"
	}
	return "<UNSET>"
}

func ValidationFromString(s string) (Validation, error) {
	switch s {
	case "Unknown":
		return Validation_Unknown, nil
	case "CorrectSignature":
		return Validation_CorrectSignature, nil
	case "RTMVolumeNotFound":
		return Validation_RTMVolumeNotFound, nil
	case "RTMSignatureNotFound":
		return Validation_RTMSignatureNotFound, nil
	case "PSBDisabled":
		return Validation_PSBDisabled, nil
	case "InvalidFormat":
		return Validation_InvalidFormat, nil
	case "IncorrectSignature":
		return Validation_IncorrectSignature, nil
	}
	return Validation(0), fmt.Errorf("not a valid Validation string")
}

func ValidationPtr(v Validation) *Validation { return &v }

func (p Validation) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *Validation) UnmarshalText(text []byte) error {
	q, err := ValidationFromString(string(text))
	if err != nil {
		return err
	}
	*p = q
	return nil
}

func (p *Validation) Scan(value interface{}) error {
	v, ok := value.(int64)
	if !ok {
		return errors.New("Scan value is not int64")
	}
	*p = Validation(v)
	return nil
}

func (p *Validation) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return int64(*p), nil
}

// Attributes:
//   - VendorID
//   - KeyRevisionID
//   - PlatformModelID
type PlatformBindingInfo struct {
	VendorID        int16 `thrift:"VendorID,1" db:"VendorID" json:"VendorID"`
	KeyRevisionID   int8  `thrift:"KeyRevisionID,2" db:"KeyRevisionID" json:"KeyRevisionID"`
	PlatformModelID int8  `thrift:"PlatformModelID,3" db:"PlatformModelID" json:"PlatformModelID"`
}

func NewPlatformBindingInfo() *PlatformBindingInfo {
	return &PlatformBindingInfo{}
}

func (p *PlatformBindingInfo) GetVendorID() int16 {
	return p.VendorID
}

func (p *PlatformBindingInfo) GetKeyRevisionID() int8 {
	return p.KeyRevisionID
}

func (p *PlatformBindingInfo) GetPlatformModelID() int8 {
	return p.PlatformModelID
}
func (p *PlatformBindingInfo) Read(ctx context.Context, iprot thrift.TProtocol) error {
	if _, err := iprot.ReadStructBegin(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
	}

	for {
		_, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
		if err != nil {
			return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
		}
		if fieldTypeId == thrift.STOP {
			break
		}
		switch fieldId {
		case 1:
			if fieldTypeId == thrift.I16 {
				if err := p.ReadField1(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 2:
			if fieldTypeId == thrift.BYTE {
				if err := p.ReadField2(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 3:
			if fieldTypeId == thrift.BYTE {
				if err := p.ReadField3(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		default:
			if err := iprot.Skip(ctx, fieldTypeId); err != nil {
				return err
			}
		}
		if err := iprot.ReadFieldEnd(ctx); err != nil {
			return err
		}
	}
	if err := iprot.ReadStructEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
	}
	return nil
}

func (p *PlatformBindingInfo) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadI16(ctx); err != nil {
		return thrift.PrependError("error reading field 1: ", err)
	} else {
		p.VendorID = v
	}
	return nil
}

func (p *PlatformBindingInfo) ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadByte(ctx); err != nil {
		return thrift.PrependError("error reading field 2: ", err)
	} else {
		temp := int8(v)
		p.KeyRevisionID = temp
	}
	return nil
}

func (p *PlatformBindingInfo) ReadField3(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadByte(ctx); err != nil {
		return thrift.PrependError("error reading field 3: ", err)
	} else {
		temp := int8(v)
		p.PlatformModelID = temp
	}
	return nil
}

func (p *PlatformBindingInfo) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "PlatformBindingInfo"); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err)
	}
	if p != nil {
		if err := p.writeField1(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField2(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField3(ctx, oprot); err != nil {
			return err
		}
	}
	if err := oprot.WriteFieldStop(ctx); err != nil {
		return thrift.PrependError("write field stop error: ", err)
	}
	if err := oprot.WriteStructEnd(ctx); err != nil {
		return thrift.PrependError("write struct stop error: ", err)
	}
	return nil
}

func (p *PlatformBindingInfo) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "VendorID", thrift.I16, 1); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:VendorID: ", p), err)
	}
	if err := oprot.WriteI16(ctx, int16(p.VendorID)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.VendorID (1) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 1:VendorID: ", p), err)
	}
	return err
}

func (p *PlatformBindingInfo) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "KeyRevisionID", thrift.BYTE, 2); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:KeyRevisionID: ", p), err)
	}
	if err := oprot.WriteByte(ctx, int8(p.KeyRevisionID)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.KeyRevisionID (2) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 2:KeyRevisionID: ", p), err)
	}
	return err
}

func (p *PlatformBindingInfo) writeField3(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "PlatformModelID", thrift.BYTE, 3); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 3:PlatformModelID: ", p), err)
	}
	if err := oprot.WriteByte(ctx, int8(p.PlatformModelID)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.PlatformModelID (3) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 3:PlatformModelID: ", p), err)
	}
	return err
}

func (p *PlatformBindingInfo) Equals(other *PlatformBindingInfo) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if p.VendorID != other.VendorID {
		return false
	}
	if p.KeyRevisionID != other.KeyRevisionID {
		return false
	}
	if p.PlatformModelID != other.PlatformModelID {
		return false
	}
	return true
}

func (p *PlatformBindingInfo) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("PlatformBindingInfo(%+v)", *p)
}

// Attributes:
//   - DisableBIOSKeyAntiRollback
//   - DisableAMDBIOSKeyUse
//   - DisableSecureDebugUnlock
type SecurityFeatureVector struct {
	DisableBIOSKeyAntiRollback bool `thrift:"DisableBIOSKeyAntiRollback,1" db:"DisableBIOSKeyAntiRollback" json:"DisableBIOSKeyAntiRollback"`
	DisableAMDBIOSKeyUse       bool `thrift:"DisableAMDBIOSKeyUse,2" db:"DisableAMDBIOSKeyUse" json:"DisableAMDBIOSKeyUse"`
	DisableSecureDebugUnlock   bool `thrift:"DisableSecureDebugUnlock,3" db:"DisableSecureDebugUnlock" json:"DisableSecureDebugUnlock"`
}

func NewSecurityFeatureVector() *SecurityFeatureVector {
	return &SecurityFeatureVector{}
}

func (p *SecurityFeatureVector) GetDisableBIOSKeyAntiRollback() bool {
	return p.DisableBIOSKeyAntiRollback
}

func (p *SecurityFeatureVector) GetDisableAMDBIOSKeyUse() bool {
	return p.DisableAMDBIOSKeyUse
}

func (p *SecurityFeatureVector) GetDisableSecureDebugUnlock() bool {
	return p.DisableSecureDebugUnlock
}
func (p *SecurityFeatureVector) Read(ctx context.Context, iprot thrift.TProtocol) error {
	if _, err := iprot.ReadStructBegin(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
	}

	for {
		_, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
		if err != nil {
			return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
		}
		if fieldTypeId == thrift.STOP {
			break
		}
		switch fieldId {
		case 1:
			if fieldTypeId == thrift.BOOL {
				if err := p.ReadField1(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 2:
			if fieldTypeId == thrift.BOOL {
				if err := p.ReadField2(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 3:
			if fieldTypeId == thrift.BOOL {
				if err := p.ReadField3(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		default:
			if err := iprot.Skip(ctx, fieldTypeId); err != nil {
				return err
			}
		}
		if err := iprot.ReadFieldEnd(ctx); err != nil {
			return err
		}
	}
	if err := iprot.ReadStructEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
	}
	return nil
}

func (p *SecurityFeatureVector) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadBool(ctx); err != nil {
		return thrift.PrependError("error reading field 1: ", err)
	} else {
		p.DisableBIOSKeyAntiRollback = v
	}
	return nil
}

func (p *SecurityFeatureVector) ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadBool(ctx); err != nil {
		return thrift.PrependError("error reading field 2: ", err)
	} else {
		p.DisableAMDBIOSKeyUse = v
	}
	return nil
}

func (p *SecurityFeatureVector) ReadField3(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadBool(ctx); err != nil {
		return thrift.PrependError("error reading field 3: ", err)
	} else {
		p.DisableSecureDebugUnlock = v
	}
	return nil
}

func (p *SecurityFeatureVector) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "SecurityFeatureVector"); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err)
	}
	if p != nil {
		if err := p.writeField1(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField2(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField3(ctx, oprot); err != nil {
			return err
		}
	}
	if err := oprot.WriteFieldStop(ctx); err != nil {
		return thrift.PrependError("write field stop error: ", err)
	}
	if err := oprot.WriteStructEnd(ctx); err != nil {
		return thrift.PrependError("write struct stop error: ", err)
	}
	return nil
}

func (p *SecurityFeatureVector) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "DisableBIOSKeyAntiRollback", thrift.BOOL, 1); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:DisableBIOSKeyAntiRollback: ", p), err)
	}
	if err := oprot.WriteBool(ctx, bool(p.DisableBIOSKeyAntiRollback)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.DisableBIOSKeyAntiRollback (1) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 1:DisableBIOSKeyAntiRollback: ", p), err)
	}
	return err
}

func (p *SecurityFeatureVector) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "DisableAMDBIOSKeyUse", thrift.BOOL, 2); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:DisableAMDBIOSKeyUse: ", p), err)
	}
	if err := oprot.WriteBool(ctx, bool(p.DisableAMDBIOSKeyUse)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.DisableAMDBIOSKeyUse (2) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 2:DisableAMDBIOSKeyUse: ", p), err)
	}
	return err
}

func (p *SecurityFeatureVector) writeField3(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "DisableSecureDebugUnlock", thrift.BOOL, 3); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 3:DisableSecureDebugUnlock: ", p), err)
	}
	if err := oprot.WriteBool(ctx, bool(p.DisableSecureDebugUnlock)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.DisableSecureDebugUnlock (3) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 3:DisableSecureDebugUnlock: ", p), err)
	}
	return err
}

func (p *SecurityFeatureVector) Equals(other *SecurityFeatureVector) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if p.DisableBIOSKeyAntiRollback != other.DisableBIOSKeyAntiRollback {
		return false
	}
	if p.DisableAMDBIOSKeyUse != other.DisableAMDBIOSKeyUse {
		return false
	}
	if p.DisableSecureDebugUnlock != other.DisableSecureDebugUnlock {
		return false
	}
	return true
}

func (p *SecurityFeatureVector) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("SecurityFeatureVector(%+v)", *p)
}

// Attributes:
//   - BIOSDirectoryLevel
//   - ValidationResult_
//   - ValidationDescription
//   - PlatformInfo
//   - SecurityFeatures
type BIOSRTMVolume struct {
	BIOSDirectoryLevel    int8                   `thrift:"BIOSDirectoryLevel,1" db:"BIOSDirectoryLevel" json:"BIOSDirectoryLevel"`
	ValidationResult_     Validation             `thrift:"ValidationResult,2" db:"ValidationResult" json:"ValidationResult"`
	ValidationDescription string                 `thrift:"ValidationDescription,3" db:"ValidationDescription" json:"ValidationDescription"`
	PlatformInfo          *PlatformBindingInfo   `thrift:"PlatformInfo,4" db:"PlatformInfo" json:"PlatformInfo,omitempty"`
	SecurityFeatures      *SecurityFeatureVector `thrift:"SecurityFeatures,5" db:"SecurityFeatures" json:"SecurityFeatures,omitempty"`
}

func NewBIOSRTMVolume() *BIOSRTMVolume {
	return &BIOSRTMVolume{}
}

func (p *BIOSRTMVolume) GetBIOSDirectoryLevel() int8 {
	return p.BIOSDirectoryLevel
}

func (p *BIOSRTMVolume) GetValidationResult_() Validation {
	return p.ValidationResult_
}

func (p *BIOSRTMVolume) GetValidationDescription() string {
	return p.ValidationDescription
}

var BIOSRTMVolume_PlatformInfo_DEFAULT *PlatformBindingInfo

func (p *BIOSRTMVolume) GetPlatformInfo() *PlatformBindingInfo {
	if !p.IsSetPlatformInfo() {
		return BIOSRTMVolume_PlatformInfo_DEFAULT
	}
	return p.PlatformInfo
}

var BIOSRTMVolume_SecurityFeatures_DEFAULT *SecurityFeatureVector

func (p *BIOSRTMVolume) GetSecurityFeatures() *SecurityFeatureVector {
	if !p.IsSetSecurityFeatures() {
		return BIOSRTMVolume_SecurityFeatures_DEFAULT
	}
	return p.SecurityFeatures
}
func (p *BIOSRTMVolume) IsSetPlatformInfo() bool {
	return p.PlatformInfo != nil
}

func (p *BIOSRTMVolume) IsSetSecurityFeatures() bool {
	return p.SecurityFeatures != nil
}

func (p *BIOSRTMVolume) Read(ctx context.Context, iprot thrift.TProtocol) error {
	if _, err := iprot.ReadStructBegin(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
	}

	for {
		_, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
		if err != nil {
			return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
		}
		if fieldTypeId == thrift.STOP {
			break
		}
		switch fieldId {
		case 1:
			if fieldTypeId == thrift.BYTE {
				if err := p.ReadField1(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 2:
			if fieldTypeId == thrift.I32 {
				if err := p.ReadField2(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 3:
			if fieldTypeId == thrift.STRING {
				if err := p.ReadField3(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 4:
			if fieldTypeId == thrift.STRUCT {
				if err := p.ReadField4(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		case 5:
			if fieldTypeId == thrift.STRUCT {
				if err := p.ReadField5(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		default:
			if err := iprot.Skip(ctx, fieldTypeId); err != nil {
				return err
			}
		}
		if err := iprot.ReadFieldEnd(ctx); err != nil {
			return err
		}
	}
	if err := iprot.ReadStructEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
	}
	return nil
}

func (p *BIOSRTMVolume) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadByte(ctx); err != nil {
		return thrift.PrependError("error reading field 1: ", err)
	} else {
		temp := int8(v)
		p.BIOSDirectoryLevel = temp
	}
	return nil
}

func (p *BIOSRTMVolume) ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadI32(ctx); err != nil {
		return thrift.PrependError("error reading field 2: ", err)
	} else {
		temp := Validation(v)
		p.ValidationResult_ = temp
	}
	return nil
}

func (p *BIOSRTMVolume) ReadField3(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadString(ctx); err != nil {
		return thrift.PrependError("error reading field 3: ", err)
	} else {
		p.ValidationDescription = v
	}
	return nil
}

func (p *BIOSRTMVolume) ReadField4(ctx context.Context, iprot thrift.TProtocol) error {
	p.PlatformInfo = &PlatformBindingInfo{}
	if err := p.PlatformInfo.Read(ctx, iprot); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", p.PlatformInfo), err)
	}
	return nil
}

func (p *BIOSRTMVolume) ReadField5(ctx context.Context, iprot thrift.TProtocol) error {
	p.SecurityFeatures = &SecurityFeatureVector{}
	if err := p.SecurityFeatures.Read(ctx, iprot); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", p.SecurityFeatures), err)
	}
	return nil
}

func (p *BIOSRTMVolume) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "BIOSRTMVolume"); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err)
	}
	if p != nil {
		if err := p.writeField1(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField2(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField3(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField4(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField5(ctx, oprot); err != nil {
			return err
		}
	}
	if err := oprot.WriteFieldStop(ctx); err != nil {
		return thrift.PrependError("write field stop error: ", err)
	}
	if err := oprot.WriteStructEnd(ctx); err != nil {
		return thrift.PrependError("write struct stop error: ", err)
	}
	return nil
}

func (p *BIOSRTMVolume) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "BIOSDirectoryLevel", thrift.BYTE, 1); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:BIOSDirectoryLevel: ", p), err)
	}
	if err := oprot.WriteByte(ctx, int8(p.BIOSDirectoryLevel)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.BIOSDirectoryLevel (1) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 1:BIOSDirectoryLevel: ", p), err)
	}
	return err
}

func (p *BIOSRTMVolume) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "ValidationResult", thrift.I32, 2); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:ValidationResult: ", p), err)
	}
	if err := oprot.WriteI32(ctx, int32(p.ValidationResult_)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.ValidationResult (2) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 2:ValidationResult: ", p), err)
	}
	return err
}

func (p *BIOSRTMVolume) writeField3(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "ValidationDescription", thrift.STRING, 3); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 3:ValidationDescription: ", p), err)
	}
	if err := oprot.WriteString(ctx, string(p.ValidationDescription)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.ValidationDescription (3) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 3:ValidationDescription: ", p), err)
	}
	return err
}

func (p *BIOSRTMVolume) writeField4(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if p.IsSetPlatformInfo() {
		if err := oprot.WriteFieldBegin(ctx, "PlatformInfo", thrift.STRUCT, 4); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field begin error 4:PlatformInfo: ", p), err)
		}
		if err := p.PlatformInfo.Write(ctx, oprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", p.PlatformInfo), err)
		}
		if err := oprot.WriteFieldEnd(ctx); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field end error 4:PlatformInfo: ", p), err)
		}
	}
	return err
}

func (p *BIOSRTMVolume) writeField5(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if p.IsSetSecurityFeatures() {
		if err := oprot.WriteFieldBegin(ctx, "SecurityFeatures", thrift.STRUCT, 5); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field begin error 5:SecurityFeatures: ", p), err)
		}
		if err := p.SecurityFeatures.Write(ctx, oprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", p.SecurityFeatures), err)
		}
		if err := oprot.WriteFieldEnd(ctx); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field end error 5:SecurityFeatures: ", p), err)
		}
	}
	return err
}

func (p *BIOSRTMVolume) Equals(other *BIOSRTMVolume) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if p.BIOSDirectoryLevel != other.BIOSDirectoryLevel {
		return false
	}
	if p.ValidationResult_ != other.ValidationResult_ {
		return false
	}
	if p.ValidationDescription != other.ValidationDescription {
		return false
	}
	if !p.PlatformInfo.Equals(other.PlatformInfo) {
		return false
	}
	if !p.SecurityFeatures.Equals(other.SecurityFeatures) {
		return false
	}
	return true
}

func (p *BIOSRTMVolume) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("BIOSRTMVolume(%+v)", *p)
}

// Attributes:
//   - Items
type CustomReport struct {
	Items []*BIOSRTMVolume `thrift:"Items,1" db:"Items" json:"Items"`
}

func NewCustomReport() *CustomReport {
	return &CustomReport{}
}

func (p *CustomReport) GetItems() []*BIOSRTMVolume {
	return p.Items
}
func (p *CustomReport) Read(ctx context.Context, iprot thrift.TProtocol) error {
	if _, err := iprot.ReadStructBegin(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
	}

	for {
		_, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
		if err != nil {
			return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
		}
		if fieldTypeId == thrift.STOP {
			break
		}
		switch fieldId {
		case 1:
			if fieldTypeId == thrift.LIST {
				if err := p.ReadField1(ctx, iprot); err != nil {
					return err
				}
			} else {
				if err := iprot.Skip(ctx, fieldTypeId); err != nil {
					return err
				}
			}
		default:
			if err := iprot.Skip(ctx, fieldTypeId); err != nil {
				return err
			}
		}
		if err := iprot.ReadFieldEnd(ctx); err != nil {
			return err
		}
	}
	if err := iprot.ReadStructEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
	}
	return nil
}

func (p *CustomReport) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	_, size, err := iprot.ReadListBegin(ctx)
	if err != nil {
		return thrift.PrependError("error reading list begin: ", err)
	}
	tSlice := make([]*BIOSRTMVolume, 0, size)
	p.Items = tSlice
	for i := 0; i < size; i++ {
		_elem0 := &BIOSRTMVolume{}
		if err := _elem0.Read(ctx, iprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", _elem0), err)
		}
		p.Items = append(p.Items, _elem0)
	}
	if err := iprot.ReadListEnd(ctx); err != nil {
		return thrift.PrependError("error reading list end: ", err)
	}
	return nil
}

func (p *CustomReport) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "CustomReport"); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err)
	}
	if p != nil {
		if err := p.writeField1(ctx, oprot); err != nil {
			return err
		}
	}
	if err := oprot.WriteFieldStop(ctx); err != nil {
		return thrift.PrependError("write field stop error: ", err)
	}
	if err := oprot.WriteStructEnd(ctx); err != nil {
		return thrift.PrependError("write struct stop error: ", err)
	}
	return nil
}

func (p *CustomReport) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "Items", thrift.LIST, 1); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:Items: ", p), err)
	}
	if err := oprot.WriteListBegin(ctx, thrift.STRUCT, len(p.Items)); err != nil {
		return thrift.PrependError("error writing list begin: ", err)
	}
	for _, v := range p.Items {
		if err := v.Write(ctx, oprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", v), err)
		}
	}
	if err := oprot.WriteListEnd(ctx); err != nil {
		return thrift.PrependError("error writing list end: ", err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 1:Items: ", p), err)
	}
	return err
}

func (p *CustomReport) Equals(other *CustomReport) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if len(p.Items) != len(other.Items) {
		return false
	}
	for i, _tgt := range p.Items {
		_src1 := other.Items[i]
		if !_tgt.Equals(_src1) {
			return false
		}
	}
	return true
}

func (p *CustomReport) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("CustomReport(%+v)", *p)
}
