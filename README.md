# rust_ASC

**rust_ASC is a stateless Android APK and DEX decompiler with millisecond cross-reference search, written in Rust.** It queries the compiled artifact directly instead of building a global index, so there is no preprocessing step, no persistent cache, and no multi-gigabyte memory footprint.

It is the Rust implementation of [MG1937/ASC](https://github.com/MG1937/ASC), the Python reference project, and preserves the same source layout, data structures, control flow and runtime behavior. On the CLI workloads below it is approximately **10× faster** than the Python version.

Presented at Black Hat Europe Arsenal: [Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive](https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834).

Repository links:

- Python reference implementation: [MG1937/ASC](https://github.com/MG1937/ASC)
- Rust implementation: [MG1937/rust_ASC](https://github.com/MG1937/rust_ASC)
- Full-APK pseudocode exporter: [MG1937/radguard](https://github.com/MG1937/radguard)

https://github.com/user-attachments/assets/f1f71a75-1eca-4647-89ce-406ed2c63c6b

## Features

- Search code references for strings, types, methods, and fields across every DEX in an APK.
- Locate and decompile one class directly from an APK.
- List classes and defined methods, and decode `AndroidManifest.xml`.
- Export pseudocode for every class in an APK with the public API of [MG1937/radguard](https://github.com/MG1937/radguard).
- Handle multi-DEX APKs and DEX 041 logical containers.
- Use memory-mapped APK access and no on-disk cache.
- Expose CLI queries as MCP tools over stdio.

## Why it is fast

- Stateless by design: no preprocessing, no global index build, no disk cache.
- The APK is memory-mapped, and only the DEX entries a query needs are inflated.
- Cross-DEX scans run in parallel, so a search over dozens of DEX files stays in the millisecond range.
- R8 output is already highly structured. Searches jump to candidate offsets directly instead of rebuilding a bloated cross-reference database.
- On a hit, rust_ASC decompiles the class directly from the containing DEX without rebuilding it. It falls back to rebuilding a minimal self-consistent DEX in memory only when direct decompilation fails for that class; `--debug` logs which path was taken.

## Build

`radguard` is a Git submodule. Clone it with the main repository:

```bash
git clone --recurse-submodules https://github.com/MG1937/rust_ASC.git
cd rust_ASC
cargo build --release
```

For an existing checkout:

```bash
git submodule update --init --recursive
cargo build --release
```

MCP is enabled by default. Build only the original CLI with:

```bash
cargo build --release --no-default-features
```

The executable is written to:

```text
target/release/rust_ASC
```

On Windows, the executable name is `rust_ASC.exe`.

## Command Line Usage

Thread control is consistent across `getclass`, `listclass`, `listmethod`, `liststring`, `findrefs`, and `export`:

- Use only `--thread <N>`.
- Put `--thread` immediately after the subcommand.
- If omitted, the command uses the number returned by Rust's `available_parallelism()` API.

```bash
# Print version.
rust_ASC -V

# Search every code reference to a string (with optional truncation or match omission).
rust_ASC findrefs --thread 10 --debug app.apk string https://
rust_ASC findrefs app.apk string https:// --max-match 80
rust_ASC findrefs app.apk string https:// --no-match
rust_ASC findrefs --json app.apk string https://

# Search a type (accepts dotted or Dalvik form), method, or field.
rust_ASC findrefs --thread 10 app.apk type com.example.Main
rust_ASC findrefs --thread 10 app.apk method onCreate --class com.example.Main
rust_ASC findrefs --thread 10 app.apk field apiKey --class com.example.Main

# Search subclasses or interface implementors.
rust_ASC findrefs --thread 10 app.apk extends android.app.Activity
rust_ASC findrefs --thread 10 app.apk impl android.os.IInterface

# Treat --class as a fuzzy descriptor substring instead of an exact name.
rust_ASC findrefs --thread 10 app.apk method notify --class poc --fuzzy-class

# Decompile one or multiple classes from an APK, or emit structured JSON with member references.
rust_ASC getclass --thread 10 --debug app.apk com.example.Main
rust_ASC getclass --thread 10 app.apk com.example.Main com.example.Second
rust_ASC getclass --thread 10 --classes-file classes.txt app.apk
rust_ASC getclass --json --classes-file classes.txt app.apk -o classes.json

# List all classes, optionally filtered by package/class prefix or as JSON.
rust_ASC listclass --thread 10 app.apk
rust_ASC listclass --thread 10 --prefix com.example app.apk
rust_ASC listclass --json app.apk

# List method definitions without decompiling, optionally filtered by class/name or as JSON.
rust_ASC listmethod --thread 10 app.apk
rust_ASC listmethod --class com.example.Main -f onCreate app.apk
rust_ASC listmethod --json app.apk -o methods.json

# List string pool values, optionally filtered by substring, deduplicated (-u/--unique), or as JSON.
rust_ASC liststring --thread 10 app.apk
rust_ASC liststring -u -f https app.apk
rust_ASC liststring --json -u app.apk -o strings.json

# Decode AndroidManifest.xml.
rust_ASC getmanifest app.apk -o AndroidManifest.xml

# Export pseudocode for all or filtered classes to the required output directory.
rust_ASC export --thread 10 --debug app.apk output
rust_ASC export --prefix com.example app.apk output
rust_ASC export --classes-file classes.txt app.apk output
```

`getclass` accepts one or more class names on the command line and/or `--classes-file <file>` (one class per line, `#` comments allowed). Passing `--json` always emits a JSON array where each element includes `class`, `status`, `dex`, `source`, and `member_references` (`start`, `end`, `kind`, `class`, `name`, `descriptor`, `declaration`, `synthetic`).

`findrefs` takes `string`, `type`, `extends`, `impl`, `method`, or `field`. `extends` and `impl` print matching class descriptors; the rest print referencing methods. `type` accepts both dotted names (`com.example.Main`) and Dalvik descriptors (`Lcom/example/Main;`). For `string`, `--max-match <N>` truncates long matched constants and `--no-match` omits the `matched=(...)` suffix. Passing `--json` emits a structured JSON array. For `method` and `field`, `--class` is an exact dotted name or Dalvik descriptor, and `--fuzzy-class` makes it a case sensitive substring. `-o` also writes the output to a file.

`listmethod` prints one Dalvik method descriptor per line, for example `Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V`. It lists only methods defined in class data, in DEX/class/declaration order with duplicates preserved. `--class` takes an exact dotted name or descriptor; `-f` is a case insensitive name substring; `--json` emits a JSON array. `-o` writes to a file instead of stdout.

`liststring` prints one string pool value per line, straight from the DEX string table, including literals nothing references. Order is DEX central-directory then string index; duplicates across DEX files are preserved unless `-u` / `--unique` is passed. `-f` is a case insensitive substring filter, while `findrefs string` is case sensitive. `--json` emits a JSON array. `-o` writes to a file instead of stdout.

`export` writes one `.java` pseudocode file per selected class under package-relative paths in the output directory, using the parallel APK pipeline from [MG1937/radguard](https://github.com/MG1937/radguard). `--prefix` and `--classes-file` filter classes before decompilation; if a filter matches no classes or any class in `--classes-file` is missing from the APK, `export` exits with status `1`. `--debug` logs the export lifecycle.

## MCP

`rust_ASC mcp` runs a stdio MCP server that exposes the CLI commands as tools: `getclass`, `listclass`, `listmethod`, `liststring`, `getmanifest`, `findrefs`, and `export`. Calls execute in-process and reuse an LRU cache of memory-mapped APK archives and parsed central directories keyed by `(path, len, mtime)`.

- `getclass` accepts `apk_path`, optional `class_name`, `classes`, `classes_file`, `json`, `thread`, and `output`.
- `listclass` accepts `apk_path`, optional `prefix`, `json`, `thread`, and `output`.
- `listmethod` accepts `apk_path`, optional `class_name`, `filter`, `json`, `thread`, and `output`.
- `liststring` accepts `apk_path`, optional `filter`, `unique`, `json`, `thread`, and `output`.
- `findrefs` accepts `apk_path`, `query` (`string`, `type`, `extends`, `impl`, `method`, or `field`), optional `json`, `thread`, and `output`. `string` queries also accept optional `max_match` and `no_match`.
- `export` accepts `apk_path`, `output`, optional `prefix`, `classes_file`, and `thread`.

Configure it in your MCP client:

```json
{
  "mcpServers": {
    "asc": {
      "command": "/absolute/path/to/rust_ASC",
      "args": ["mcp"]
    }
  }
}
```

## Benchmark

### rust_ASC vs JADX

Same workloads. JADX figures come from the ASC benchmark suite.

**Global string cross-reference search**

| | TelegramX (59 MB) | WhatsApp (130 MB) | Grab (228 MB) | TencentQQ (318 MB) |
| --- | ---: | ---: | ---: | ---: |
| rust_ASC | 55 ms | 67 ms | 118 ms | 136 ms |
| JADX | 20 s | 32 s | 2m14s | 8m2s |

rust_ASC is 364x to 3,544x faster than JADX for global string xref search.

**Single-class decompile**

| | TelegramX (59 MB) | WhatsApp (130 MB) | Grab (228 MB) | TencentQQ (318 MB) |
| --- | ---: | ---: | ---: | ---: |
| rust_ASC | 79 ms | 70 ms | 111 ms | 118 ms |
| JADX | 6 s | 15 s | 37 s | 1m32s |

rust_ASC is 76x to 780x faster than JADX for single-class decompile.

**CLI peak memory**

| | TelegramX (59 MB) | WhatsApp (130 MB) | Grab (228 MB) | TencentQQ (318 MB) |
| --- | ---: | ---: | ---: | ---: |
| rust_ASC | 32 MB | 116 MB | 358 MB | 443 MB |
| JADX | 1,016 MB | 2.1 GB | 7.1 GB | 13.2 GB |

rust_ASC uses 19x to 32x less memory than JADX for CLI operation.

**Disk cache**

| | TelegramX | WhatsApp | Grab | TencentQQ |
| --- | ---: | ---: | ---: | ---: |
| rust_ASC | 0 MB | 0 MB | 0 MB | 0 MB |
| JADX | 119 MB | 30 MB | 127 MB | 322 MB |

rust_ASC stays fully in memory with zero disk cache, while JADX writes up to 322 MB.

Because every query is stateless, an agent can analyze hundreds of APKs at once, even on weak machines.

### rust_ASC CLI details

The following measurements use CLI commands with no cache, no preprocessing, and direct searches of every code reference to the string `https://`.

| APK | APK size | CLI string-reference search | CLI single-class decompile | CLI RSS peak | Persistent cache |
| --- | ---: | ---: | ---: | ---: | ---: |
| TelegramX | 59 MB | 55 ms | 79 ms — `com.coremedia.iso.boxes.AlbumBox` | 32 MB | 0 MB |
| WhatsApp | 130 MB | 67 ms | 70 ms — `com.whatsapp.apollo.Apollo` | 116 MB | 0 MB |
| Grab | 228 MB | 118 ms | 111 ms — `com.grab.arrears.view.ArrearsPickUpDropOffView` | 358 MB | 0 MB |
| TencentQQ | 318 MB | 136 ms | 118 ms — `com.tencent.icgame.game.trtc.roomservice.voiceroom.a.b` | 443 MB | 0 MB |

- **CLI string-reference search**: search all code references to `https://` directly from the APK, without cache or preprocessing.
- **CLI single-class decompile**: locate and decompile the named class directly from the APK.
- **Persistent cache**: disk cache written by the tool after command completion.

## Full APK Pseudocode Export Benchmark

Full-APK pseudocode export is provided through [MG1937/radguard](https://github.com/MG1937/radguard)'s public `export_to_directory` API and uses its shared parallel APK export pipeline. The following benchmark fully decompiles **TencentQQ.apk** (383 MB, 41 DEX files).

| Workers | Wall time | Speedup vs. 8 workers | Notes |
| ---: | ---: | ---: | --- |
| 8 | 7.4 s | 1.00× | 725% CPU, 827,840 KiB max RSS |
| 16 | 4.17 s | 1.78× | Reported run |
| 32 | 2.56 s | 2.89× | 2166% CPU, 2,639,588 KiB max RSS |

The worker count is a global export budget. The exporter overlaps APK/DEX processing with class decompilation while bounding per-DEX concurrent class work.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
