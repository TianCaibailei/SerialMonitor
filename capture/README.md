# What we found in E:\ProgramFiles\CommMonitor12\CommMonitor.exe

CommMonitor.exe is a program for Windows, built for x86_64 (64-bit). Its internal names were removed (stripped), so most functions will have generated names.

Evidence ev_11a266e4826d26476bdcec5b7869eca9899e4278f26ece061c69b01e6d11b4b8.

```json
{
  "architecture": "x86_64",
  "bits": 64,
  "dotnet_arch": null,
  "entry_point": "0xaf19a0",
  "format": "pe",
  "format_name": "PE (Windows)",
  "kind": "executable",
  "libraries": [
    "SHFolder.dll",
    "advapi32.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "gdi32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "msvcrt.dll",
    "netapi32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "shell32.dll",
    "user32.dll",
    "version.dll",
    "wininet.dll",
    "winspool.drv",
    "wsock32.dll",
    "wtsapi32.dll",
    "msimg32.dll",
    "windowscodecs.dll",
    "uxtheme.dll",
    "imm32.dll",
    "DWMAPI.DLL"
  ],
  "next_steps": [
    {
      "tool": "core_overview_show",
      "why": "a one-page summary: sections, imports, counts"
    },
    {
      "tool": "native_functions_list",
      "why": "every function we found"
    },
    {
      "tool": "native_strings_find",
      "why": "find text the program shows or uses"
    },
    {
      "tool": "native_function_study",
      "why": "a full dossier on one function (start with main or the entry point)"
    },
    {
      "tool": "core_feature_find",
      "why": "follow a word you see in the app to the code behind it"
    },
    {
      "tool": "native_pe_resources_list",
      "why": "icons, version information and the manifest"
    }
  ],
  "operating_system": "Windows",
  "plain_english": "CommMonitor.exe is a program for Windows, built for x86_64 (64-bit). Its internal names were removed (stripped), so most functions will have generated names.",
  "recommended_toolsets": [
    "core",
    "native",
    "formats"
  ],
  "stripped": true,
  "symbol_table_stripped": true,
  "toolchain_hints": []
}
```

## Ghidra

Ghidra couldn't analyse E:\ProgramFiles\CommMonitor12\CommMonitor.exe (could not start Ghidra: Ghidra's analysis failed; see C:\Users\1\AppData\Roaming\craft-anything\engines\ghidra-cache\f22270250b0cf9fc-f2dfab6faedc84f0.log), so decompiling uses the built-in decompiler.
