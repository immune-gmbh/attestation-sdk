// Code generated by Thrift Compiler (0.14.0). DO NOT EDIT.

package psptypes

import(
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
	"github.com/apache/thrift/lib/go/thrift"
)

// (needed to ensure safety because of naive import list construction.)
var _ = thrift.ZERO
var _ = fmt.Printf
var _ = context.Background
var _ = time.Now
var _ = bytes.Equal

type DirectoryType int64
const (
  DirectoryType_PSPTableLevel1 DirectoryType = 0
  DirectoryType_PSPTableLevel2 DirectoryType = 1
  DirectoryType_BIOSTableLevel1 DirectoryType = 2
  DirectoryType_BIOSTableLevel2 DirectoryType = 3
)

func (p DirectoryType) String() string {
  switch p {
  case DirectoryType_PSPTableLevel1: return "PSPTableLevel1"
  case DirectoryType_PSPTableLevel2: return "PSPTableLevel2"
  case DirectoryType_BIOSTableLevel1: return "BIOSTableLevel1"
  case DirectoryType_BIOSTableLevel2: return "BIOSTableLevel2"
  }
  return "<UNSET>"
}

func DirectoryTypeFromString(s string) (DirectoryType, error) {
  switch s {
  case "PSPTableLevel1": return DirectoryType_PSPTableLevel1, nil 
  case "PSPTableLevel2": return DirectoryType_PSPTableLevel2, nil 
  case "BIOSTableLevel1": return DirectoryType_BIOSTableLevel1, nil 
  case "BIOSTableLevel2": return DirectoryType_BIOSTableLevel2, nil 
  }
  return DirectoryType(0), fmt.Errorf("not a valid DirectoryType string")
}


func DirectoryTypePtr(v DirectoryType) *DirectoryType { return &v }

func (p DirectoryType) MarshalText() ([]byte, error) {
return []byte(p.String()), nil
}

func (p *DirectoryType) UnmarshalText(text []byte) error {
q, err := DirectoryTypeFromString(string(text))
if (err != nil) {
return err
}
*p = q
return nil
}

func (p *DirectoryType) Scan(value interface{}) error {
v, ok := value.(int64)
if !ok {
return errors.New("Scan value is not int64")
}
*p = DirectoryType(v)
return nil
}

func (p * DirectoryType) Value() (driver.Value, error) {
  if p == nil {
    return nil, nil
  }
return int64(*p), nil
}
type PSPDirectoryTableEntryType int64
const (
  PSPDirectoryTableEntryType_AMDPublicKeyEntry PSPDirectoryTableEntryType = 0
  PSPDirectoryTableEntryType_PSPBootloaderFirmwareEntry PSPDirectoryTableEntryType = 1
  PSPDirectoryTableEntryType_PSPRecoveryBootlader PSPDirectoryTableEntryType = 3
  PSPDirectoryTableEntryType_SMUOffChipFirmwareEntry PSPDirectoryTableEntryType = 8
  PSPDirectoryTableEntryType_ABLPublicKey PSPDirectoryTableEntryType = 10
  PSPDirectoryTableEntryType_SMUOffChipFirmware2Entry PSPDirectoryTableEntryType = 18
  PSPDirectoryTableEntryType_UnlockDebugImageEntry PSPDirectoryTableEntryType = 19
  PSPDirectoryTableEntryType_SecurityPolicyBinaryEntry PSPDirectoryTableEntryType = 36
  PSPDirectoryTableEntryType_MP5FirmwareEntry PSPDirectoryTableEntryType = 42
  PSPDirectoryTableEntryType_AGESABinary0Entry PSPDirectoryTableEntryType = 48
  PSPDirectoryTableEntryType_SEVCodeEntry PSPDirectoryTableEntryType = 57
  PSPDirectoryTableEntryType_PSPDirectoryTableLevel2Entry PSPDirectoryTableEntryType = 64
  PSPDirectoryTableEntryType_DXIOPHYSRAMFirmwareEntry PSPDirectoryTableEntryType = 66
  PSPDirectoryTableEntryType_DRTMTAEntry PSPDirectoryTableEntryType = 71
  PSPDirectoryTableEntryType_KeyDatabaseEntry PSPDirectoryTableEntryType = 80
)

func (p PSPDirectoryTableEntryType) String() string {
  switch p {
  case PSPDirectoryTableEntryType_AMDPublicKeyEntry: return "AMDPublicKeyEntry"
  case PSPDirectoryTableEntryType_PSPBootloaderFirmwareEntry: return "PSPBootloaderFirmwareEntry"
  case PSPDirectoryTableEntryType_PSPRecoveryBootlader: return "PSPRecoveryBootlader"
  case PSPDirectoryTableEntryType_SMUOffChipFirmwareEntry: return "SMUOffChipFirmwareEntry"
  case PSPDirectoryTableEntryType_ABLPublicKey: return "ABLPublicKey"
  case PSPDirectoryTableEntryType_SMUOffChipFirmware2Entry: return "SMUOffChipFirmware2Entry"
  case PSPDirectoryTableEntryType_UnlockDebugImageEntry: return "UnlockDebugImageEntry"
  case PSPDirectoryTableEntryType_SecurityPolicyBinaryEntry: return "SecurityPolicyBinaryEntry"
  case PSPDirectoryTableEntryType_MP5FirmwareEntry: return "MP5FirmwareEntry"
  case PSPDirectoryTableEntryType_AGESABinary0Entry: return "AGESABinary0Entry"
  case PSPDirectoryTableEntryType_SEVCodeEntry: return "SEVCodeEntry"
  case PSPDirectoryTableEntryType_PSPDirectoryTableLevel2Entry: return "PSPDirectoryTableLevel2Entry"
  case PSPDirectoryTableEntryType_DXIOPHYSRAMFirmwareEntry: return "DXIOPHYSRAMFirmwareEntry"
  case PSPDirectoryTableEntryType_DRTMTAEntry: return "DRTMTAEntry"
  case PSPDirectoryTableEntryType_KeyDatabaseEntry: return "KeyDatabaseEntry"
  }
  return "<UNSET>"
}

func PSPDirectoryTableEntryTypeFromString(s string) (PSPDirectoryTableEntryType, error) {
  switch s {
  case "AMDPublicKeyEntry": return PSPDirectoryTableEntryType_AMDPublicKeyEntry, nil 
  case "PSPBootloaderFirmwareEntry": return PSPDirectoryTableEntryType_PSPBootloaderFirmwareEntry, nil 
  case "PSPRecoveryBootlader": return PSPDirectoryTableEntryType_PSPRecoveryBootlader, nil 
  case "SMUOffChipFirmwareEntry": return PSPDirectoryTableEntryType_SMUOffChipFirmwareEntry, nil 
  case "ABLPublicKey": return PSPDirectoryTableEntryType_ABLPublicKey, nil 
  case "SMUOffChipFirmware2Entry": return PSPDirectoryTableEntryType_SMUOffChipFirmware2Entry, nil 
  case "UnlockDebugImageEntry": return PSPDirectoryTableEntryType_UnlockDebugImageEntry, nil 
  case "SecurityPolicyBinaryEntry": return PSPDirectoryTableEntryType_SecurityPolicyBinaryEntry, nil 
  case "MP5FirmwareEntry": return PSPDirectoryTableEntryType_MP5FirmwareEntry, nil 
  case "AGESABinary0Entry": return PSPDirectoryTableEntryType_AGESABinary0Entry, nil 
  case "SEVCodeEntry": return PSPDirectoryTableEntryType_SEVCodeEntry, nil 
  case "PSPDirectoryTableLevel2Entry": return PSPDirectoryTableEntryType_PSPDirectoryTableLevel2Entry, nil 
  case "DXIOPHYSRAMFirmwareEntry": return PSPDirectoryTableEntryType_DXIOPHYSRAMFirmwareEntry, nil 
  case "DRTMTAEntry": return PSPDirectoryTableEntryType_DRTMTAEntry, nil 
  case "KeyDatabaseEntry": return PSPDirectoryTableEntryType_KeyDatabaseEntry, nil 
  }
  return PSPDirectoryTableEntryType(0), fmt.Errorf("not a valid PSPDirectoryTableEntryType string")
}


func PSPDirectoryTableEntryTypePtr(v PSPDirectoryTableEntryType) *PSPDirectoryTableEntryType { return &v }

func (p PSPDirectoryTableEntryType) MarshalText() ([]byte, error) {
return []byte(p.String()), nil
}

func (p *PSPDirectoryTableEntryType) UnmarshalText(text []byte) error {
q, err := PSPDirectoryTableEntryTypeFromString(string(text))
if (err != nil) {
return err
}
*p = q
return nil
}

func (p *PSPDirectoryTableEntryType) Scan(value interface{}) error {
v, ok := value.(int64)
if !ok {
return errors.New("Scan value is not int64")
}
*p = PSPDirectoryTableEntryType(v)
return nil
}

func (p * PSPDirectoryTableEntryType) Value() (driver.Value, error) {
  if p == nil {
    return nil, nil
  }
return int64(*p), nil
}
type BIOSDirectoryTableEntryType int64
const (
  BIOSDirectoryTableEntryType_BIOSRTMSignatureEntry BIOSDirectoryTableEntryType = 7
  BIOSDirectoryTableEntryType_APCBDataEntry BIOSDirectoryTableEntryType = 96
  BIOSDirectoryTableEntryType_APOBBinaryEntry BIOSDirectoryTableEntryType = 97
  BIOSDirectoryTableEntryType_BIOSRTMVolumeEntry BIOSDirectoryTableEntryType = 98
  BIOSDirectoryTableEntryType_PMUFirmwareInstructionsEntry BIOSDirectoryTableEntryType = 100
  BIOSDirectoryTableEntryType_PMUFirmwareDataEntry BIOSDirectoryTableEntryType = 101
  BIOSDirectoryTableEntryType_MicrocodePatchEntry BIOSDirectoryTableEntryType = 102
  BIOSDirectoryTableEntryType_APCBDataBackupEntry BIOSDirectoryTableEntryType = 104
  BIOSDirectoryTableEntryType_VideoInterpreterEntry BIOSDirectoryTableEntryType = 105
  BIOSDirectoryTableEntryType_BIOSDirectoryTableLevel2Entry BIOSDirectoryTableEntryType = 106
)

func (p BIOSDirectoryTableEntryType) String() string {
  switch p {
  case BIOSDirectoryTableEntryType_BIOSRTMSignatureEntry: return "BIOSRTMSignatureEntry"
  case BIOSDirectoryTableEntryType_APCBDataEntry: return "APCBDataEntry"
  case BIOSDirectoryTableEntryType_APOBBinaryEntry: return "APOBBinaryEntry"
  case BIOSDirectoryTableEntryType_BIOSRTMVolumeEntry: return "BIOSRTMVolumeEntry"
  case BIOSDirectoryTableEntryType_PMUFirmwareInstructionsEntry: return "PMUFirmwareInstructionsEntry"
  case BIOSDirectoryTableEntryType_PMUFirmwareDataEntry: return "PMUFirmwareDataEntry"
  case BIOSDirectoryTableEntryType_MicrocodePatchEntry: return "MicrocodePatchEntry"
  case BIOSDirectoryTableEntryType_APCBDataBackupEntry: return "APCBDataBackupEntry"
  case BIOSDirectoryTableEntryType_VideoInterpreterEntry: return "VideoInterpreterEntry"
  case BIOSDirectoryTableEntryType_BIOSDirectoryTableLevel2Entry: return "BIOSDirectoryTableLevel2Entry"
  }
  return "<UNSET>"
}

func BIOSDirectoryTableEntryTypeFromString(s string) (BIOSDirectoryTableEntryType, error) {
  switch s {
  case "BIOSRTMSignatureEntry": return BIOSDirectoryTableEntryType_BIOSRTMSignatureEntry, nil 
  case "APCBDataEntry": return BIOSDirectoryTableEntryType_APCBDataEntry, nil 
  case "APOBBinaryEntry": return BIOSDirectoryTableEntryType_APOBBinaryEntry, nil 
  case "BIOSRTMVolumeEntry": return BIOSDirectoryTableEntryType_BIOSRTMVolumeEntry, nil 
  case "PMUFirmwareInstructionsEntry": return BIOSDirectoryTableEntryType_PMUFirmwareInstructionsEntry, nil 
  case "PMUFirmwareDataEntry": return BIOSDirectoryTableEntryType_PMUFirmwareDataEntry, nil 
  case "MicrocodePatchEntry": return BIOSDirectoryTableEntryType_MicrocodePatchEntry, nil 
  case "APCBDataBackupEntry": return BIOSDirectoryTableEntryType_APCBDataBackupEntry, nil 
  case "VideoInterpreterEntry": return BIOSDirectoryTableEntryType_VideoInterpreterEntry, nil 
  case "BIOSDirectoryTableLevel2Entry": return BIOSDirectoryTableEntryType_BIOSDirectoryTableLevel2Entry, nil 
  }
  return BIOSDirectoryTableEntryType(0), fmt.Errorf("not a valid BIOSDirectoryTableEntryType string")
}


func BIOSDirectoryTableEntryTypePtr(v BIOSDirectoryTableEntryType) *BIOSDirectoryTableEntryType { return &v }

func (p BIOSDirectoryTableEntryType) MarshalText() ([]byte, error) {
return []byte(p.String()), nil
}

func (p *BIOSDirectoryTableEntryType) UnmarshalText(text []byte) error {
q, err := BIOSDirectoryTableEntryTypeFromString(string(text))
if (err != nil) {
return err
}
*p = q
return nil
}

func (p *BIOSDirectoryTableEntryType) Scan(value interface{}) error {
v, ok := value.(int64)
if !ok {
return errors.New("Scan value is not int64")
}
*p = BIOSDirectoryTableEntryType(v)
return nil
}

func (p * BIOSDirectoryTableEntryType) Value() (driver.Value, error) {
  if p == nil {
    return nil, nil
  }
return int64(*p), nil
}
// Attributes:
//  - Entry
//  - Instance
type BIOSDirectoryEntry struct {
  Entry BIOSDirectoryTableEntryType `thrift:"Entry,1" db:"Entry" json:"Entry"`
  Instance int16 `thrift:"Instance,2" db:"Instance" json:"Instance"`
}

func NewBIOSDirectoryEntry() *BIOSDirectoryEntry {
  return &BIOSDirectoryEntry{}
}


func (p *BIOSDirectoryEntry) GetEntry() BIOSDirectoryTableEntryType {
  return p.Entry
}

func (p *BIOSDirectoryEntry) GetInstance() int16 {
  return p.Instance
}
func (p *BIOSDirectoryEntry) Read(ctx context.Context, iprot thrift.TProtocol) error {
  if _, err := iprot.ReadStructBegin(ctx); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
  }


  for {
    _, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
    if err != nil {
      return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
    }
    if fieldTypeId == thrift.STOP { break; }
    switch fieldId {
    case 1:
      if fieldTypeId == thrift.I32 {
        if err := p.ReadField1(ctx, iprot); err != nil {
          return err
        }
      } else {
        if err := iprot.Skip(ctx, fieldTypeId); err != nil {
          return err
        }
      }
    case 2:
      if fieldTypeId == thrift.I16 {
        if err := p.ReadField2(ctx, iprot); err != nil {
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

func (p *BIOSDirectoryEntry)  ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
  if v, err := iprot.ReadI32(ctx); err != nil {
  return thrift.PrependError("error reading field 1: ", err)
} else {
  temp := BIOSDirectoryTableEntryType(v)
  p.Entry = temp
}
  return nil
}

func (p *BIOSDirectoryEntry)  ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
  if v, err := iprot.ReadI16(ctx); err != nil {
  return thrift.PrependError("error reading field 2: ", err)
} else {
  p.Instance = v
}
  return nil
}

func (p *BIOSDirectoryEntry) Write(ctx context.Context, oprot thrift.TProtocol) error {
  if err := oprot.WriteStructBegin(ctx, "BIOSDirectoryEntry"); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err) }
  if p != nil {
    if err := p.writeField1(ctx, oprot); err != nil { return err }
    if err := p.writeField2(ctx, oprot); err != nil { return err }
  }
  if err := oprot.WriteFieldStop(ctx); err != nil {
    return thrift.PrependError("write field stop error: ", err) }
  if err := oprot.WriteStructEnd(ctx); err != nil {
    return thrift.PrependError("write struct stop error: ", err) }
  return nil
}

func (p *BIOSDirectoryEntry) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
  if err := oprot.WriteFieldBegin(ctx, "Entry", thrift.I32, 1); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:Entry: ", p), err) }
  if err := oprot.WriteI32(ctx, int32(p.Entry)); err != nil {
  return thrift.PrependError(fmt.Sprintf("%T.Entry (1) field write error: ", p), err) }
  if err := oprot.WriteFieldEnd(ctx); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write field end error 1:Entry: ", p), err) }
  return err
}

func (p *BIOSDirectoryEntry) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
  if err := oprot.WriteFieldBegin(ctx, "Instance", thrift.I16, 2); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:Instance: ", p), err) }
  if err := oprot.WriteI16(ctx, int16(p.Instance)); err != nil {
  return thrift.PrependError(fmt.Sprintf("%T.Instance (2) field write error: ", p), err) }
  if err := oprot.WriteFieldEnd(ctx); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write field end error 2:Instance: ", p), err) }
  return err
}

func (p *BIOSDirectoryEntry) Equals(other *BIOSDirectoryEntry) bool {
  if p == other {
    return true
  } else if p == nil || other == nil {
    return false
  }
  if p.Entry != other.Entry { return false }
  if p.Instance != other.Instance { return false }
  return true
}

func (p *BIOSDirectoryEntry) String() string {
  if p == nil {
    return "<nil>"
  }
  return fmt.Sprintf("BIOSDirectoryEntry(%+v)", *p)
}

// Attributes:
//  - PSPEntry
//  - BIOSEntry
type DirectoryEntry struct {
  PSPEntry *PSPDirectoryTableEntryType `thrift:"PSPEntry,1" db:"PSPEntry" json:"PSPEntry,omitempty"`
  BIOSEntry *BIOSDirectoryEntry `thrift:"BIOSEntry,2" db:"BIOSEntry" json:"BIOSEntry,omitempty"`
}

func NewDirectoryEntry() *DirectoryEntry {
  return &DirectoryEntry{}
}

var DirectoryEntry_PSPEntry_DEFAULT PSPDirectoryTableEntryType
func (p *DirectoryEntry) GetPSPEntry() PSPDirectoryTableEntryType {
  if !p.IsSetPSPEntry() {
    return DirectoryEntry_PSPEntry_DEFAULT
  }
return *p.PSPEntry
}
var DirectoryEntry_BIOSEntry_DEFAULT *BIOSDirectoryEntry
func (p *DirectoryEntry) GetBIOSEntry() *BIOSDirectoryEntry {
  if !p.IsSetBIOSEntry() {
    return DirectoryEntry_BIOSEntry_DEFAULT
  }
return p.BIOSEntry
}
func (p *DirectoryEntry) CountSetFieldsDirectoryEntry() int {
  count := 0
  if (p.IsSetPSPEntry()) {
    count++
  }
  if (p.IsSetBIOSEntry()) {
    count++
  }
  return count

}

func (p *DirectoryEntry) IsSetPSPEntry() bool {
  return p.PSPEntry != nil
}

func (p *DirectoryEntry) IsSetBIOSEntry() bool {
  return p.BIOSEntry != nil
}

func (p *DirectoryEntry) Read(ctx context.Context, iprot thrift.TProtocol) error {
  if _, err := iprot.ReadStructBegin(ctx); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
  }


  for {
    _, fieldTypeId, fieldId, err := iprot.ReadFieldBegin(ctx)
    if err != nil {
      return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
    }
    if fieldTypeId == thrift.STOP { break; }
    switch fieldId {
    case 1:
      if fieldTypeId == thrift.I32 {
        if err := p.ReadField1(ctx, iprot); err != nil {
          return err
        }
      } else {
        if err := iprot.Skip(ctx, fieldTypeId); err != nil {
          return err
        }
      }
    case 2:
      if fieldTypeId == thrift.STRUCT {
        if err := p.ReadField2(ctx, iprot); err != nil {
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

func (p *DirectoryEntry)  ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
  if v, err := iprot.ReadI32(ctx); err != nil {
  return thrift.PrependError("error reading field 1: ", err)
} else {
  temp := PSPDirectoryTableEntryType(v)
  p.PSPEntry = &temp
}
  return nil
}

func (p *DirectoryEntry)  ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
  p.BIOSEntry = &BIOSDirectoryEntry{}
  if err := p.BIOSEntry.Read(ctx, iprot); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", p.BIOSEntry), err)
  }
  return nil
}

func (p *DirectoryEntry) Write(ctx context.Context, oprot thrift.TProtocol) error {
  if c := p.CountSetFieldsDirectoryEntry(); c != 1 {
    return fmt.Errorf("%T write union: exactly one field must be set (%d set).", p, c)
  }
  if err := oprot.WriteStructBegin(ctx, "DirectoryEntry"); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err) }
  if p != nil {
    if err := p.writeField1(ctx, oprot); err != nil { return err }
    if err := p.writeField2(ctx, oprot); err != nil { return err }
  }
  if err := oprot.WriteFieldStop(ctx); err != nil {
    return thrift.PrependError("write field stop error: ", err) }
  if err := oprot.WriteStructEnd(ctx); err != nil {
    return thrift.PrependError("write struct stop error: ", err) }
  return nil
}

func (p *DirectoryEntry) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
  if p.IsSetPSPEntry() {
    if err := oprot.WriteFieldBegin(ctx, "PSPEntry", thrift.I32, 1); err != nil {
      return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:PSPEntry: ", p), err) }
    if err := oprot.WriteI32(ctx, int32(*p.PSPEntry)); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T.PSPEntry (1) field write error: ", p), err) }
    if err := oprot.WriteFieldEnd(ctx); err != nil {
      return thrift.PrependError(fmt.Sprintf("%T write field end error 1:PSPEntry: ", p), err) }
  }
  return err
}

func (p *DirectoryEntry) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
  if p.IsSetBIOSEntry() {
    if err := oprot.WriteFieldBegin(ctx, "BIOSEntry", thrift.STRUCT, 2); err != nil {
      return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:BIOSEntry: ", p), err) }
    if err := p.BIOSEntry.Write(ctx, oprot); err != nil {
      return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", p.BIOSEntry), err)
    }
    if err := oprot.WriteFieldEnd(ctx); err != nil {
      return thrift.PrependError(fmt.Sprintf("%T write field end error 2:BIOSEntry: ", p), err) }
  }
  return err
}

func (p *DirectoryEntry) Equals(other *DirectoryEntry) bool {
  if p == other {
    return true
  } else if p == nil || other == nil {
    return false
  }
  if p.PSPEntry != other.PSPEntry {
    if p.PSPEntry == nil || other.PSPEntry == nil {
      return false
    }
    if (*p.PSPEntry) != (*other.PSPEntry) { return false }
  }
  if !p.BIOSEntry.Equals(other.BIOSEntry) { return false }
  return true
}

func (p *DirectoryEntry) String() string {
  if p == nil {
    return "<nil>"
  }
  return fmt.Sprintf("DirectoryEntry(%+v)", *p)
}

