//go:build linux
// +build linux

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

package flashrom

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
)

// IOMemEntry is one entry of `/proc/iomem`
type IOMemEntry struct {
	Start       uint64
	End         uint64
	Description string
	Children    IOMemEntries
}

// IOMemEntries is the result of GetIOMem
type IOMemEntries []*IOMemEntry

// GetIOMem returns the content of `/proc/iomem`
func GetIOMem(opts ...Option) (IOMemEntries, error) {
	return newFlashrom(opts...).getIOMem()
}

func (f *flashrom) getIOMem() (IOMemEntries, error) {
	iomemFile, err := os.OpenFile(f.Config.IOMemPath, os.O_RDONLY, 0000)
	if err != nil {
		return nil, fmt.Errorf("unable to open '%s': %w", f.Config.IOMemPath, err)
	}

	iomemBytes, err := io.ReadAll(iomemFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read '%s': %w", f.Config.IOMemPath, err)
	}

	iomem, err := ParseIOMem(iomemBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse iomem '%s': %w", iomemBytes, err)
	}

	return iomem, err
}

// ParseIOMem parses `/proc/iomem` contents.
func ParseIOMem(iomemBytes []byte) (IOMemEntries, error) {
	entries, _, err := parseIOMem(bytes.Split(iomemBytes, []byte("\n")), nil)
	return entries, err
}

func parseIOMem(iomemLines [][]byte, intend []byte) (IOMemEntries, [][]byte, error) {
	/*
		Example of input data:

		bffdc000-bfffffff : Reserved
		c0000000-febfffff : PCI Bus 0000:00
		  feb80000-febbffff : 0000:00:02.0
		  febec000-febeffff : 0000:00:02.0
		    febec000-febeffff : virtio-pci-modern
		  febf0000-febf3fff : 0000:00:03.0

		We:
		1. Split line "000f0000-000fffff : Reserved" by " : ".
		2. Split "000f0000-000fffff" by "-".
		3. Include all children after the list (which has a higher intend).
	*/

	var result IOMemEntries
	var curEntry *IOMemEntry

	nextLevelIntent := intend
	nextLevelIntent = append(nextLevelIntent, []byte("  ")...)
	for {
		if len(iomemLines) == 0 {
			break
		}
		line := iomemLines[0]
		switch {
		case !bytes.HasPrefix(line, intend):
			return result, iomemLines, nil
		case bytes.HasPrefix(line, nextLevelIntent):
			var err error
			if curEntry == nil {
				return nil, nil, fmt.Errorf("invalid format, extra nesting level")
			}
			curEntry.Children, iomemLines, err = parseIOMem(iomemLines, nextLevelIntent)
			if err != nil {
				return nil, nil, err
			}
			continue
		}

		iomemLines = iomemLines[1:]
		if len(line) == 0 {
			continue
		}

		leftRight := bytes.Split(line, []byte(" : "))
		if len(leftRight) != 2 {
			return nil, nil, fmt.Errorf("invalid format, expected two parts in '%s': %d != 2",
				line, len(leftRight))
		}
		left := leftRight[0]
		right := leftRight[1]

		curEntry = &IOMemEntry{}
		result = append(result, curEntry)

		rangeBytes := bytes.Split(left, []byte("-"))
		if len(rangeBytes) != 2 {
			return nil, nil, fmt.Errorf("invalid format of the left part, expected two parts in '%s': %d != 2",
				left, len(rangeBytes))
		}
		startBytes := bytes.Trim(rangeBytes[0], " ")
		endBytes := rangeBytes[1]
		start, err := strconv.ParseUint(string(startBytes), 16, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse starting offset '%s': %w", startBytes, err)
		}
		end, err := strconv.ParseUint(string(endBytes), 16, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse ending offset '%s': %w", endBytes, err)
		}

		curEntry.Start = start
		curEntry.End = end
		curEntry.Description = string(right)
	}

	return result, nil, nil
}
