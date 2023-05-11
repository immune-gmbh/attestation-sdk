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

namespace go pkg.analyzers.amd.apcbsectokens.report.generated.apcbsecanalysis

const string APCBSecurityTokensAnalyzerID = "APCBSecurityTokens";

union TokenValue {
  1: bool Boolean;
  2: byte Byte;
  3: i16 Word;
  4: i32 DWord;
}

enum TokenID {
  PSPMeasureConfig = 1,
  PSPEnableDebugMode = 2,
  PSPErrorDisplay = 3,
  PSPStopOnError = 4,
}

struct Token {
  1: TokenID ID;
  2: byte PriorityMask;
  3: i16 BoardMask;
  4: TokenValue Value;
}

struct BIOSDirectoryTokens {
  1: byte BIOSDirectoryLevel;
  2: list<Token> Tokens;
}

struct CustomReport {
  1: list<BIOSDirectoryTokens> DirectoryTokens;
}
