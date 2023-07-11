//go:build ignore
// +build ignore

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

	"github.com/google/uuid"
	"golang.org/x/sync/semaphore"
)

type JobID uuid.UUID

type Task struct {
	// immutable
	Analyzer Analyzer
	Input    AnalyzerInput

	// mutable
	Output       AnalyzerOutput
	Dependencies Tasks
}

type Tasks []*Task

func CreateAnalysisJob(request *Request) (*Job, error) {

	// Create tasks

	var tasks Tasks
	taskDataDependencies := map[*Task][]dataType{}
	dataSampleToTask := map[dataType]*Task{}
	for _, subJobRequest := range request.AnalysisList {
		registryItem := globalRegistry.getAnalyzerByInputType(normTypeOf(subJobRequest.Input))
		if registryItem == nil {
			return nil, ErrRegistry{Err: ErrNoAnalyzerForInput{InputType: normTypeOf(subJobRequest.Input)}}
		}

		task := &Task{
			Analyzer: registryItem.Analyzer,
			Input:    subJobRequest.Input,
		}
		taskDataDependencies[task] = registryItem.DataDependencies
		dataSampleToTask[registryItem.OutputType] = task

		tasks = append(tasks, task)
	}

	// Calculate dependencies among tasks (fill fields "tasks[i].Dependencies")

	for _, parentTask := range tasks {
		_ = *parentTask // make sure `parentTask` is pointer here

		var children Tasks
		for _, dep := range taskDataDependencies[parentTask] {
			childTask := dataSampleToTask[dep]
			if childTask == nil {
				return nil, ErrInput{Err: ErrNoAnalyzerForOutput{OutputType: dep}}
			}
			children = append(children, childTask)
		}

		parentTask.Dependencies = children
	}

	// Return the result

	return &Job{
		ID:    JobID(uuid.New()),
		Tasks: tasks,
	}, nil
}

type Job struct {
	ID    JobID
	Tasks Tasks
}

func (job *Job) Start(nCPU uint) *JobProcess {
	sem := semaphore.NewWeighted(int64(nCPU))
	proc := &JobProcess{
		Job: job,
	}
	proc.start(sem)
	return proc
}

type JobProcess struct {
	*Job
	wg sync.WaitGroup
}

func (job *JobProcess) start(sem *semaphore.Weighted) {
	for _, task := range job.Tasks {
		for _, dep := range task.Dependencies {

		}
	}
}

func (job *JobProcess) Wait() {

}
