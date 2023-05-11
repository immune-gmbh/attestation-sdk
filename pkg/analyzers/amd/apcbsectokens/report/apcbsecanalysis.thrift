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
