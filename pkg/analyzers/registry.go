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
package analyzers

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr"
)

// AnalyzerFactory represents a factory method for new analyzers
type AnalyzerFactory[inputType any] func() analysis.Analyzer[inputType]

// Registry provides access to all standalone firmware analyzers
type Registry struct {
	// TODO: use the input type as the key in the map (it is safer)
	// TODO: also generalize the factory, instead of using `any`
	analyzerFactories map[analysis.AnalyzerID]any
}

// Add registers provided analyzer
func Add[inputType any](r *Registry, id analysis.AnalyzerID, analyzerFactory AnalyzerFactory[inputType]) error {
	if analyzerFactory == nil {
		return fmt.Errorf("analyzer should not be nil")
	}
	if _, found := r.analyzerFactories[id]; found {
		return fmt.Errorf("analyzer with id '%s' is already registered", id)
	}
	if len(id) == 0 {
		return fmt.Errorf("empty analyzer id")
	}
	r.analyzerFactories[id] = analyzerFactory
	return nil
}

// Get returns a new instance of required analyzer by id
//
// TODO: remove `id analysis.AnalyzerID`, use the `inputType` to find a proper registry.
func Get[inputType any](r *Registry, id analysis.AnalyzerID) analysis.Analyzer[inputType] {
	analyzerFactory := r.analyzerFactories[id]
	if analyzerFactory == nil {
		return nil
	}
	return analyzerFactory.(AnalyzerFactory[inputType])()
}

// IDs returns a list of IDs of all registered analyzers
func (r *Registry) IDs() []analysis.AnalyzerID {
	result := make([]analysis.AnalyzerID, 0, len(r.analyzerFactories))
	for id := range r.analyzerFactories {
		result = append(result, id)
	}
	return result
}

// NewRegistry creates a new Registry instance
func NewRegistry() *Registry {
	return &Registry{
		analyzerFactories: make(map[analysis.AnalyzerID]any),
	}
}

// NewRegistryWithKnownAnalyzers creates a new Registry instance and registers all analyzers from the analyzers subpackages
func NewRegistryWithKnownAnalyzers() (*Registry, error) {
	r := NewRegistry()
	if err := Add(r, pspsignature.ID, pspsignature.New); err != nil {
		return nil, err
	}
	if err := Add(r, diffmeasuredboot.ID, diffmeasuredboot.New); err != nil {
		return nil, err
	}
	if err := Add(r, intelacm.ID, intelacm.New); err != nil {
		return nil, err
	}
	if err := Add(r, reproducepcr.ID, reproducepcr.New); err != nil {
		return nil, err
	}
	if err := Add(r, biosrtmvolume.ID, biosrtmvolume.New); err != nil {
		return nil, err
	}
	if err := Add(r, apcbsectokens.ID, apcbsectokens.New); err != nil {
		return nil, err
	}
	return r, nil
}
