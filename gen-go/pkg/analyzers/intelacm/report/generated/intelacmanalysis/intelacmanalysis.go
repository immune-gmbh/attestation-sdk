// Code generated by Thrift Compiler (0.14.0). DO NOT EDIT.

package intelacmanalysis

import (
	"bytes"
	"context"
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

// Attributes:
//   - Date
//   - SESVN
//   - TXTSVN
type ACMInfo struct {
	Date   int32 `thrift:"Date,1" db:"Date" json:"Date"`
	SESVN  int16 `thrift:"SESVN,2" db:"SESVN" json:"SESVN"`
	TXTSVN int16 `thrift:"TXTSVN,3" db:"TXTSVN" json:"TXTSVN"`
}

func NewACMInfo() *ACMInfo {
	return &ACMInfo{}
}

func (p *ACMInfo) GetDate() int32 {
	return p.Date
}

func (p *ACMInfo) GetSESVN() int16 {
	return p.SESVN
}

func (p *ACMInfo) GetTXTSVN() int16 {
	return p.TXTSVN
}
func (p *ACMInfo) Read(ctx context.Context, iprot thrift.TProtocol) error {
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
		case 3:
			if fieldTypeId == thrift.I16 {
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

func (p *ACMInfo) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadI32(ctx); err != nil {
		return thrift.PrependError("error reading field 1: ", err)
	} else {
		p.Date = v
	}
	return nil
}

func (p *ACMInfo) ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadI16(ctx); err != nil {
		return thrift.PrependError("error reading field 2: ", err)
	} else {
		p.SESVN = v
	}
	return nil
}

func (p *ACMInfo) ReadField3(ctx context.Context, iprot thrift.TProtocol) error {
	if v, err := iprot.ReadI16(ctx); err != nil {
		return thrift.PrependError("error reading field 3: ", err)
	} else {
		p.TXTSVN = v
	}
	return nil
}

func (p *ACMInfo) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "ACMInfo"); err != nil {
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

func (p *ACMInfo) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "Date", thrift.I32, 1); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:Date: ", p), err)
	}
	if err := oprot.WriteI32(ctx, int32(p.Date)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.Date (1) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 1:Date: ", p), err)
	}
	return err
}

func (p *ACMInfo) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "SESVN", thrift.I16, 2); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:SESVN: ", p), err)
	}
	if err := oprot.WriteI16(ctx, int16(p.SESVN)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.SESVN (2) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 2:SESVN: ", p), err)
	}
	return err
}

func (p *ACMInfo) writeField3(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if err := oprot.WriteFieldBegin(ctx, "TXTSVN", thrift.I16, 3); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field begin error 3:TXTSVN: ", p), err)
	}
	if err := oprot.WriteI16(ctx, int16(p.TXTSVN)); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T.TXTSVN (3) field write error: ", p), err)
	}
	if err := oprot.WriteFieldEnd(ctx); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write field end error 3:TXTSVN: ", p), err)
	}
	return err
}

func (p *ACMInfo) Equals(other *ACMInfo) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if p.Date != other.Date {
		return false
	}
	if p.SESVN != other.SESVN {
		return false
	}
	if p.TXTSVN != other.TXTSVN {
		return false
	}
	return true
}

func (p *ACMInfo) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ACMInfo(%+v)", *p)
}

// Attributes:
//   - Original
//   - Received
type IntelACMDiagInfo struct {
	Original *ACMInfo `thrift:"Original,1" db:"Original" json:"Original,omitempty"`
	Received *ACMInfo `thrift:"Received,2" db:"Received" json:"Received,omitempty"`
}

func NewIntelACMDiagInfo() *IntelACMDiagInfo {
	return &IntelACMDiagInfo{}
}

var IntelACMDiagInfo_Original_DEFAULT *ACMInfo

func (p *IntelACMDiagInfo) GetOriginal() *ACMInfo {
	if !p.IsSetOriginal() {
		return IntelACMDiagInfo_Original_DEFAULT
	}
	return p.Original
}

var IntelACMDiagInfo_Received_DEFAULT *ACMInfo

func (p *IntelACMDiagInfo) GetReceived() *ACMInfo {
	if !p.IsSetReceived() {
		return IntelACMDiagInfo_Received_DEFAULT
	}
	return p.Received
}
func (p *IntelACMDiagInfo) IsSetOriginal() bool {
	return p.Original != nil
}

func (p *IntelACMDiagInfo) IsSetReceived() bool {
	return p.Received != nil
}

func (p *IntelACMDiagInfo) Read(ctx context.Context, iprot thrift.TProtocol) error {
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
			if fieldTypeId == thrift.STRUCT {
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

func (p *IntelACMDiagInfo) ReadField1(ctx context.Context, iprot thrift.TProtocol) error {
	p.Original = &ACMInfo{}
	if err := p.Original.Read(ctx, iprot); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", p.Original), err)
	}
	return nil
}

func (p *IntelACMDiagInfo) ReadField2(ctx context.Context, iprot thrift.TProtocol) error {
	p.Received = &ACMInfo{}
	if err := p.Received.Read(ctx, iprot); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T error reading struct: ", p.Received), err)
	}
	return nil
}

func (p *IntelACMDiagInfo) Write(ctx context.Context, oprot thrift.TProtocol) error {
	if err := oprot.WriteStructBegin(ctx, "IntelACMDiagInfo"); err != nil {
		return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err)
	}
	if p != nil {
		if err := p.writeField1(ctx, oprot); err != nil {
			return err
		}
		if err := p.writeField2(ctx, oprot); err != nil {
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

func (p *IntelACMDiagInfo) writeField1(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if p.IsSetOriginal() {
		if err := oprot.WriteFieldBegin(ctx, "Original", thrift.STRUCT, 1); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field begin error 1:Original: ", p), err)
		}
		if err := p.Original.Write(ctx, oprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", p.Original), err)
		}
		if err := oprot.WriteFieldEnd(ctx); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field end error 1:Original: ", p), err)
		}
	}
	return err
}

func (p *IntelACMDiagInfo) writeField2(ctx context.Context, oprot thrift.TProtocol) (err error) {
	if p.IsSetReceived() {
		if err := oprot.WriteFieldBegin(ctx, "Received", thrift.STRUCT, 2); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field begin error 2:Received: ", p), err)
		}
		if err := p.Received.Write(ctx, oprot); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T error writing struct: ", p.Received), err)
		}
		if err := oprot.WriteFieldEnd(ctx); err != nil {
			return thrift.PrependError(fmt.Sprintf("%T write field end error 2:Received: ", p), err)
		}
	}
	return err
}

func (p *IntelACMDiagInfo) Equals(other *IntelACMDiagInfo) bool {
	if p == other {
		return true
	} else if p == nil || other == nil {
		return false
	}
	if !p.Original.Equals(other.Original) {
		return false
	}
	if !p.Received.Equals(other.Received) {
		return false
	}
	return true
}

func (p *IntelACMDiagInfo) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("IntelACMDiagInfo(%+v)", *p)
}
