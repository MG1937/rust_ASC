# rust_ASC

`rust_ASC` is a one-to-one Rust port of [MG1937/ASC](https://github.com/MG1937/ASC), the Python implementation of ASC. The Rust implementation preserves the corresponding source layout, data structures, control flow, function roles, and runtime behavior while targeting substantially lower command-line latency and memory overhead.

On the reported CLI workloads below, `rust_ASC` is approximately **10× faster** than the Python ASC implementation. It remains stateless: no preprocessing is required before a query, and it writes no persistent cache to disk.

Repository links:

- Python reference implementation: [MG1937/ASC](https://github.com/MG1937/ASC)
- Rust implementation: [MG1937/rust_ASC](https://github.com/MG1937/rust_ASC)
- Full-APK pseudocode exporter: [MG1937/radguard](https://github.com/MG1937/radguard)

https://github.com/user-attachments/assets/f1f71a75-1eca-4647-89ce-406ed2c63c6b

## Features

- Search code references for strings, types, methods, and fields across every DEX in an APK.
- Locate and decompile one class directly from an APK.
- List classes and decode `AndroidManifest.xml`.
- Export pseudocode for every class in an APK with the public API of [MG1937/radguard](https://github.com/MG1937/radguard).
- Handle multi-DEX APKs and DEX 041 logical containers.
- Use memory-mapped APK access and no on-disk cache.

## Build

```bash
cargo build --release
```

The executable is written to:

```text
target/release/rust_ASC
```

On Windows, the executable name is `rust_ASC.exe`.

## Command Line Usage

Thread control is consistent across `getclass`, `listclass`, `findrefs`, and `export`:

- Use only `--thread <N>`.
- Put `--thread` immediately after the subcommand.
- If omitted, the command uses the number returned by Rust's `available_parallelism()` API.

```bash
# Search every code reference to a string.
rust_ASC findrefs --thread 10 --debug app.apk string https://

# Search a type, method, or field.
rust_ASC findrefs --thread 10 app.apk type com.example.Main
rust_ASC findrefs --thread 10 app.apk method onCreate --class com.example.Main
rust_ASC findrefs --thread 10 app.apk field apiKey --class com.example.Main

# Decompile one class from an APK.
rust_ASC getclass --thread 10 --debug app.apk com.example.Main
rust_ASC getclass --thread 10 app.apk com.example.Main -o Main.java

# List all classes, optionally filtered by package/class prefix.
rust_ASC listclass --thread 10 app.apk
rust_ASC listclass --thread 10 --prefix com.example app.apk

# Decode AndroidManifest.xml.
rust_ASC getmanifest app.apk -o AndroidManifest.xml

# Export pseudocode for every class to the required output directory.
rust_ASC export --thread 10 --debug app.apk output
```

`export` writes one `.java` pseudocode file per class under package-relative paths in the output directory. Its multi-threaded APK export pipeline is supplied by [MG1937/radguard](https://github.com/MG1937/radguard). With `--debug`, it reports the APK export lifecycle and worker activity.

## CLI Benchmark

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
