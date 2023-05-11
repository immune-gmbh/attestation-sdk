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
include "../pkg/analyzers/amd/apcbsectokens/report/apcbsecanalysis.thrift"
include "../pkg/analyzers/amd/biosrtmvolume/report/biosrtmanalysis.thrift"
include "../pkg/analyzers/amd/pspsignature/report/pspsignanalysis.thrift"
include "../pkg/analyzers/diffmeasuredboot/report/diffanalysis.thrift"
include "../pkg/analyzers/intelacm/report/intelacmanalysis.thrift"
include "../pkg/analyzers/reproducepcr/report/reproducepcranalysis.thrift"

namespace go if.generated.analyzerreport

enum Severity {
  SeverityUnknown = 0,
  SeverityInfo = 1,
  SeverityWarning = 2,
  SeverityCritical = 3,
}

// IssueInfo provides an ability to customise Issue by analyzers
union IssueInfo {}

// Issue describes a single found problem in firmware
struct Issue {
  // Custom is a custom information provided for issue description
  1: optional IssueInfo Custom;

  // Severity tells how important is found issue
  2: Severity Severity;

  // Description is a text description of a found problem
  3: optional string Description;
}

// ReportInfo provides an ability to customise Report by analyzers
union ReportInfo {
  1: diffanalysis.CustomReport DiffMeasuredBoot;
  2: intelacmanalysis.IntelACMDiagInfo IntelACM;
  3: reproducepcranalysis.CustomReport ReproducePCR;
  4: pspsignanalysis.CustomReport PSPSignature;
  5: biosrtmanalysis.CustomReport BIOSRTMVolume;
  6: apcbsecanalysis.CustomReport APCBSecurityTokens;
}

struct AnalyzerReport {
  // Custom is a custom information provided for Report description
  1: optional ReportInfo Custom;

  2: optional list<Issue> Issues;

  3: optional list<string> Comments;
}
