# Frida Bridge

## 📖 Overview

frida-bridge is a native JNI library that loads Frida Gadget into the
host Android process with minimal configuration. It automatically resolves the
real on‑disk paths — including inside containers that remap the filesystem —
waits for the Android Runtime to become available, and places the gadget’s
config and script files exactly where Frida expects them. No root, no APK
patching, just a single `System.loadLibrary()` call.

---

## 📋 Table of Contents

1. [Special Advantages](#-1-special-advantages)
2. [Gadget Files & Directory Layout](#-2-gadget-files--directory-layout)
3. [Delay Configuration](#%EF%B8%8F-3-delay-configuration)
4. [Usage Guide](#-4-usage-guide)
5. [Security Perspective](#%EF%B8%8F-5-security-perspective)
6. [Troubleshooting](#-6-troubleshooting)

---

## 🚀 1. Special Advantages

>🔥 **Container / VM Native Support**  
>Works inside **any container or virtual machine**. Load frida gadget in official apps/games without tampering their integrity.  


> **How to use inside a container/VM:**  
>- Implement the bridge library inside the container  
>  See [Implementation Instructions](https://github.com/muhammadrizwan87/frida-bridge#-implementation-instructions)
>- Clone the target app inside the container  
>- Place gadget files inside the app's private files directory (`<getFilesDir()>/frida`).  
>  For example, if the package is `com.example`, the path will typically be  
>  `/data/user/0/com.example/files/frida` (the `0` may be a different user ID  
>  depending on the Android profile).  
>  You can access this location via the container's rootfs.
>- Run the target app inside the container

---

## 📁 2. Gadget Files & Directory Layout

All files live under `<getFilesDir()>/frida/`:

| File | Purpose |
|---|---|
| `libfrida-gadget.so` | Frida Gadget shared library (you supply this) |
| `libfrida-gadget.config.so` | Gadget config JSON — auto-managed by the bridge |
| `libfrida-gadget.script.so` | Compiled JS agent (you supply this, for script mode) |
| `frida-bridge.cfg` | Bridge config — currently supports `delay=<seconds>` |

**Automatic path resolution**  
Whatever you put in the config’s `"path"` field (absolute, relative, real, or logical), the bridge will fix it at runtime. It copies the script file into the real gadget directory and rewrites the `"path"` to the bare filename `libfrida-gadget.script.so`. This guarantees the gadget can always find the script, even when the filesystem is remapped by a container.

---

## ⏱️ 3. Delay Configuration

Create `frida-bridge.cfg` in the same `frida/` directory:

```
delay=3
```

| Value | Behavior |
|---|---|
| absent / `0` (default) | No extra delay. Gadget loads as soon as `Application` is ready. |
| `1`–`60` | Bridge sleeps this many seconds after `Application` is ready, before loading gadget. |

Useful when your script needs the host app to finish its own
initialization (e.g. a specific `Activity` or `Service`) before hooks
become active.

---

## 💡 4. Usage Guide

### 📝 Prerequisites

- Android NDK (for native compilation)
- Termux app (for on-device building), or a desktop toolchain

> 💡 Tip:
> If you encounter issues with NDK builds or Termux setup, use the GitHub
> Actions workflow to auto-compile the source — no manual setup needed,
> builds for all architectures.

### 🛠️ Build Instructions

```bash
# Clone the repository
git clone https://github.com/muhammadrizwan87/frida-bridge.git
cd frida-bridge

# Set NDK path
export NDK_HOME=/path/to/your/ndk
# export NDK_HOME=/data/data/com.termux/files/home/android-sdk/ndk/24.0.8215888

# Build for all architectures
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. NDK_APPLICATION_MK=./jni/Application.mk

# Output will be in libs/
ls libs/
# armeabi-v7a/ arm64-v8a/ x86/ x86_64/
```

### 🚩 Build Flags

| Flag | Effect |
|---|---|
| (none, default) | Release build — only `LOGI`/`LOGW`/`LOGE` emitted |
| `-DFRIDA_BRIDGE_DEBUG` | Verbose `LOGD` output: maps dumps, real-directory listings, JNI wait progress |

Enable by uncommenting the line in `jni/Android.mk`.

### 🔀 Implementation Instructions

#### Option A: Patch an existing APK (Smali)

```smali
.method static constructor <clinit>()V
    .registers 1
    
    const-string v0, "frida-bridge"
    
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    
    return-void
.end method
```

Add `lib/<abi>/libfrida-bridge.so` for each architecture, and place gadget
files under `files/frida/` as described in section 3.

#### Option B: Integrate into your own Android project

```java
public class MyApp extends Application {
    static {
        System.loadLibrary("frida-bridge");
    }
}
```

```gradle
android {
    sourceSets {
        main {
            jniLibs.srcDirs = ['libs']
        }
    }
}
```

---

## 🛡️ 5. Security Perspective

### 🔑 What This Library Can Access

The library operates **entirely within the existing security boundary** of
the host process. It:
- ✅ Reads `/proc/self/maps` and `/proc/self/cmdline` — accessible to every process by design
- ✅ Reads/writes inside the app's own files directory — storage the process already owns
- ✅ Makes JNI calls using the app's own `JavaVM` — standard Android API
- ✅ Calls `dlopen()` on a library file already present on disk, supplied by the integrator

**No system call is made that the app itself could not make.**

### ❎ What This Library Does NOT Do

- ❌ Does not escalate privileges
- ❌ Does not communicate over the network on its own
- ❌ Does not access other apps' data
- ❌ Does not download or fetch the gadget binary — it must be supplied locally
- ❌ Does not request additional Android permissions

### 🏛️ Policy Compliance

The library loads as part of the host app's own process under the app's
UID and operates entirely within Android's standard application sandbox.

---

## 🔧 6. Troubleshooting

### 🪵 Read the Logs First
Most issues can be diagnosed with `logcat`. Filter for the tag `FridaBridge`.  
A healthy run shows this sequence:

```
I/FridaBridge: Bridge started
I/FridaBridge: Files dir: /data/…
I/FridaBridge: ART detected via maps: …
I/FridaBridge: Gadget loaded
I/FridaBridge: Bridge done
```

If you see `Gadget loaded` and `Bridge done`, **the bridge itself is working** — the problem lies in the gadget configuration, script, or environment.

### ❗ Script Not Working?
- **Script quality**: The most common cause of a silent failure is a mistake in the script itself — a call to a missing method, a removed API, or a logic error that kills the agent before hooks are applied. Test the script on a non‑container environment (real device / emulator) to confirm it works standalone.
- **Script compilation**: If your script requires compilation, use `frida-compile` and ensure the output file is named `libfrida-gadget.script.so`.
- **Config mode**: The bridge rewrites the `"path"` field; verify that the rest of the config (especially the `"interaction"` block) is correct.
- **Two‑launch behavior**: On the first launch (or after clearing app data), the bridge copies the config & script to the real path *after* the gadget initializes. The gadget only picks them up on the **next** launch. Run the app twice — the second launch should work.
- **Timing / hooks missing**: If some hooks don’t trigger, increase the `delay` value in `frida-bridge.cfg`. This gives the app more time to reach the target code before the script runs.

### 🧪 What to Check Before Opening an Issue
- Post the full `logcat` from `Bridge started` to `Bridge done` (or at least the relevant `FridaBridge` lines).
- Specify Frida Gadget version, Android version, and whether you are inside a container/VM.
- Try the same setup on a non‑container environment to isolate the issue.