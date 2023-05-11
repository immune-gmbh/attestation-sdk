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

package analyzer

import (
	"sync"
)

type analyzerRegistryItem struct {
	Analyzer         Analyzer
	InputType        dataType
	OutputType       dataType
	DataDependencies []dataType
}

type Registry struct {
	locker         sync.Mutex
	analyzers      []analyzerRegistryItem
	dataConverters []DataConverter
}

var globalRegistry = newRegistry()

func newRegistry() *Registry {
	return &Registry{}
}

func RegisterFirmwareAnalyzer(
	analyzer Analyzer,
	outputSample any,
	inputSample any,
	dataDependencies ...any,
) error {
	return globalRegistry.RegisterFirmwareAnalyzer(analyzer, outputSample, inputSample, dataDependencies...)
}

func (registry *Registry) RegisterFirmwareAnalyzer(
	analyzer Analyzer,
	outputSample any,
	inputSample any,
	dataDependencies ...any,
) error {
	registry.locker.Lock()
	defer registry.locker.Unlock()

	inputType := normTypeOf(inputSample)
	outputType := normTypeOf(outputSample)
	for _, old := range registry.analyzers {
		if old.InputType == inputType {
			return ErrAlreadyRegisteredInput{Existing: old, New: analyzer, InputType: inputType}
		}
		if old.OutputType == outputType {
			return ErrAlreadyRegisteredOutput{Existing: old, New: analyzer, OutputType: outputType}
		}
	}

	var dataDependencyTypes []dataType
	for _, dep := range dataDependencies {
		dataDependencyTypes = append(dataDependencyTypes, normTypeOf(dep))
	}

	registry.analyzers = append(registry.analyzers, analyzerRegistryItem{
		Analyzer:         analyzer,
		InputType:        inputType,
		OutputType:       outputType,
		DataDependencies: dataDependencyTypes,
	})
	return nil
}

func (registry *Registry) getAnalyzerByInputType(inputType dataType) *analyzerRegistryItem {
	registry.locker.Lock()
	defer registry.locker.Unlock()

	for _, item := range registry.analyzers {
		if item.InputType == inputType {
			return &[]analyzerRegistryItem{item}[0]
		}
	}

	return nil
}

func (registry *Registry) getAnalyzerByOutputType(outputType dataType) *analyzerRegistryItem {
	registry.locker.Lock()
	defer registry.locker.Unlock()
	for _, item := range registry.analyzers {
		if item.OutputType == outputType {
			return &[]analyzerRegistryItem{item}[0]
		}
	}

	return nil
}

func (registry *Registry) RegisterDataConverter(
	converter DataConverter,
	outputSample any,
	inputSample any,
	dataDependencies ...any,
) error {
}
