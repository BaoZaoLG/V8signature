# V8 Internal Signature Scan - libcef.dll
## Summary

The strongest V8 anchors are clustered around `0x10DE*` - `0x10DF*`.
These functions reference V8 API trace/assertion strings and are suitable for
locating V8 compile/execute/template paths in this `libcef.dll` build.

Auto-analysis was still reported as not complete by IDA MCP, but Hex-Rays and
the strings cache were available. Signatures below are IDA-style byte patterns
with wildcarded operands.

## High-Confidence Function Candidates

### `sub_10DF2150` - V8 script compiler path

- Address: `0x10DF2150`
- Size: `0x5FE` / 1534 bytes
- Basic blocks: 84
- Cyclomatic complexity: 45
- Strings:
  - `v8`
  - `V8.ScriptCompiler`
  - `v8::ScriptCompiler::CompileUnbound`
  - `disabled-by-default-v8.compile`
  - `V8.CompileScript`

Function-entry signature:

```text
55 89 E5 53 57 56 83 E4 ? 81 EC ? ? ? ? A1 ? ? ? ? 31 E8 89 84 24 ? ? ? ? A1 ? ? ? ? 85 C0 75 ? E8
```

Reference-site signatures:

```text
; xref to "v8::ScriptCompiler::CompileUnbound" at 0x10DF22C9
68 ? ? ? ? E8 ? ? ? ? 8B 87 ? ? ? ? C7 87 ? ? ? ? ? ? ? ? 31 FF

; xref to "V8.CompileScript" at 0x10DF23C2
C7 44 24 ? ? ? ? ? 89 5C 24 ? 89 4C 24 ? 89 44 24 ? 8B 45 ? 0F 57 C0

; xref to "V8.CompileScript" at 0x10DF2379
68 ? ? ? ? 56 6A ? FF 52 ? 8B 4C 24 ? 89 C3 89 54 24 ? C7 44 24 ? ? ? ? ? 85 C9 74 ? 8B 01 6A ? FF 10 8B 4C 24 ? C7 44 24 ? ? ? ? ? 85 C9 74 ? 8B 01 6A ? FF 10 8B 4C 24
```

### `sub_10DF0A40` - V8 script execution path

- Address: `0x10DF0A40`
- Size: `0x456` / 1110 bytes
- Basic blocks: 50
- Cyclomatic complexity: 24
- Strings:
  - `v8`
  - `V8.Execute`
  - `v8::Script::Run`
  - `Escape value set twice`
  - `EscapableHandleScope::Escape`

Function-entry signature status:

- Not unique within 120-byte constraint.
- Use the reference-site signature below instead.

Reference-site signature:

```text
; xref to "v8::Script::Run" at 0x10DF0B72
68 ? ? ? ? E8 ? ? ? ? 8B 87 ? ? ? ? C7 87 ? ? ? ? ? ? ? ? 8B 97
```

### `sub_10DEDE40` - FunctionTemplate SetCallHandler path

- Address: `0x10DEDE40`
- Size: `0x381` / 897 bytes
- Basic blocks: 50
- Cyclomatic complexity: 29
- Strings:
  - `FunctionTemplate already instantiated`
  - `v8::FunctionTemplate::SetCallHandler`
  - fatal error format string

Function-entry signature:

```text
55 89 E5 53 57 56 83 EC ? A1 ? ? ? ? 89 CF 31 E8 89 45 ? 8B 01 8B 48 ? F6 C1
```

Reference-site signatures:

```text
; xref to "v8::FunctionTemplate::SetCallHandler" at 0x10DEDEB2
68 ? ? ? ? FF D0 83 C4 ? C6 86 ? ? ? ? ? 8B 07

; xref to "v8::FunctionTemplate::SetCallHandler" at 0x10DEE1AA
68 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 ? E8 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 55 89 E5 53 57 56 83 EC ? A1
```

### `sub_10DED9A0` - FunctionTemplate::New path

- Address: `0x10DED9A0`
- Size: `0x102` / 258 bytes
- Basic blocks: 9
- Cyclomatic complexity: 5
- Strings:
  - `v8::FunctionTemplate::New`

Function-entry signature:

```text
55 89 E5 53 57 56 83 E4 ? 83 EC ? A1 ? ? ? ? 8B 75 ? 8D 54 24 ? 31 E8 89 44 24 ? C7 04 24 ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? A1 ? ? ? ? 85 C0 75 ? 8B 8E ? ? ? ? 8B 7D
```

Reference-site signature:

```text
; xref to "v8::FunctionTemplate::New" at 0x10DEDA0D
68 ? ? ? ? E8 ? ? ? ? 8B 9E ? ? ? ? 8B 4D
```

### `sub_10DEEF70` - FunctionTemplate::New alternate path

- Address: `0x10DEEF70`
- Size: `0x23A` / 570 bytes
- Basic blocks: 30
- Cyclomatic complexity: 16
- Strings:
  - `v8::FunctionTemplate::New`

Function-entry signature:

```text
55 89 E5 53 57 56 83 E4 ? 83 EC ? A1 ? ? ? ? 89 CB 8B 4D ? 89 D7
```

Reference-site signature:

```text
; xref to "v8::FunctionTemplate::New" at 0x10DEEFF5
68 ? ? ? ? E8 ? ? ? ? 8B B7 ? ? ? ? 8D 4C 24
```

## Shared V8 Evidence

Shared globals / strings accessed by the cluster:

- `0x14D0E1A6` `aFatalErrorInSS`: used by `sub_10DEDE40`, `sub_10DF0A40`, `sub_10DF2150`
- `0x14D0E392` `aEscapeValueSet`: used by `sub_10DF0A40`, `sub_10DF2150`
- `0x14D0E3A9` `aEscapablehandl`: used by `sub_10DF0A40`, `sub_10DF2150`
- `0x14D0E4D5` `aV8Functiontemp_0`: used by `sub_10DED9A0`, `sub_10DEEF70`
- `0x14D0E75C` `aV8`: used by `sub_10DF0A40`, `sub_10DF2150`

## Notes

- `sub_10DF2150` is the best single compile-path signature target because it
  contains multiple V8 compiler trace strings and produced a unique function
  entry signature.
- `sub_10DF0A40` is the best execute-path target, but its function entry did
  not become unique under the short signature limit. Use its `v8::Script::Run`
  xref signature instead.
- `sub_10DEDE40`, `sub_10DED9A0`, and `sub_10DEEF70` cover V8 template API
  creation/handler paths and are good secondary anchors.
