namespace go if.generated.txt_errors

exception ErrUnknown {}
exception ErrBPTIntegrity {}
exception ErrBPM {}
exception ErrBPMRevoked {}

const map<string, string> ErrorDescription = {
  "ErrUnknown": "unknown error",
  "ErrBPTIntegrity": "BPT integrity error",
  "ErrBPM": "BPM error",
  "ErrBPMRevoked": "BPM is revoked (firmware was downgraded to an insecure version, BPM SVN is decreased)",
};
