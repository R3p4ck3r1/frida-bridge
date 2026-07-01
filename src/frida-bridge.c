/*
 * frida-bridge.c
 *
 * A JNI bridge library that loads Frida Gadget into a host application
 * running inside an Android container environment.
 *
 * HOW IT WORKS
 * ============
 * Inside a container, the filesystem is remapped. The logical path returned
 * by Android APIs (e.g. getFilesDir) differs from the real path at which
 * files are actually mapped in memory:
 *
 *   Logical:  /data/user/<N>/<host_pkg>/files/frida/libfrida-gadget.so
 *   Real:     /data/data/<container_pkg>/rootfs/data/user/<N>/<host_pkg>/files/frida/libfrida-gadget.so
 *
 * Frida Gadget reads its config file from the directory where it is actually
 * mapped in memory (real path), not the logical path. This bridge resolves
 * the real path after dlopen via /proc/self/maps, then ensures config and
 * script files are present there before the next launch.
 *
 * TWO-LAUNCH BEHAVIOUR
 * ====================
 * Launch 1: dlopen discovers real path → copies config+script to real path.
 *           Gadget has already init-ed without config this launch.
 * Launch 2: Config+script already at real path before dlopen → Gadget finds
 *           them on init → correct interaction mode is active.
 *
 * BUILD FLAGS
 * ===========
 *   Default (release): minimal logs.
 *   Debug:  -DFRIDA_BRIDGE_DEBUG   enables verbose diagnostic logs.
 *
 * FILE LAYOUT (all under <files_dir>/frida/)
 * ==========================================
 *   libfrida-gadget.so         Frida Gadget shared library
 *   libfrida-gadget.config.so  Gadget config JSON (auto-managed by bridge)
 *   libfrida-gadget.script.so  Compiled JS agent (user-supplied)
 *   frida-bridge.cfg           Bridge config  (delay=<seconds>)
 */

#define _GNU_SOURCE
#include <jni.h>
#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Logging
 *
 * FRIDA_BRIDGE_DEBUG enables verbose logs at build time.
 * Release builds emit only INFO / WARN / ERROR.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define LOG_TAG "FridaBridge"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef FRIDA_BRIDGE_DEBUG
# define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
# define LOGD(...)((void) 0)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Default seconds to sleep after Application ready before loading gadget. */
#define DEFAULT_DELAY_SECS 0

/** Subdirectory under getFilesDir() that holds gadget files. */
#define GADGET_SUBDIR "frida"

/** Gadget shared library filename. */
#define GADGET_LIB_NAME "libfrida-gadget.so"

/**
 * Gadget config filename. Named with .so extension so Android's
 * ClassLoader does not strip it from APK assets on older versions.
 */
#define GADGET_CONFIG_NAME "libfrida-gadget.config.so"

/**
 * Gadget script filename. Same .so naming convention as config.
 * Must match the "path" field in the config JSON.
 */
#define GADGET_SCRIPT_NAME "libfrida-gadget.script.so"

/** Bridge-specific config file for runtime settings (e.g. delay). */
#define BRIDGE_CFG_FILE "frida-bridge.cfg"

/** Maximum seconds to wait for JavaVM to become available. */
#define JVM_WAIT_SECS 10

/**
 * Maximum seconds to wait for ART (libart.so) to be mapped into the
 * process before giving up and loading gadget anyway. The maps-based
 * check (see art_loaded_from_maps) is fast and reliable, so this can
 * be shorter than a polling interval based on dlopen probing.
 */
#define ART_WAIT_SECS 10

/** Maximum accepted value for the "delay=" setting in frida-bridge.cfg. */
#define MAX_DELAY_SECS 60

/* Global JavaVM reference, set in JNI_OnLoad. */
static _Atomic(JavaVM * ) g_jvm = NULL;
/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers — file I/O
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * copy_file() - Copy a file from src to dst using low-level fd I/O.
 *
 * Skips the copy silently if src and dst paths are identical.
 * Creates dst with mode 0644 (owner rw, group/other r).
 *
 * @src:    Absolute path of source file.
 * @dst:    Absolute path of destination file.
 * @return: 1 on success, 0 on failure.
 */
static int copy_file(const char * src,
  const char * dst) {
  if (strcmp(src, dst) == 0) {
    LOGD("copy_file: src == dst, skipping '%s'", src);
    return 1;
  }

  int sfd = open(src, O_RDONLY);
  if (sfd < 0) {
    LOGE("copy_file: cannot open src '%s': %s", src, strerror(errno));
    return 0;
  }

  int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dfd < 0) {
    LOGE("copy_file: cannot open dst '%s': %s", dst, strerror(errno));
    close(sfd);
    return 0;
  }

  char buf[8192];
  ssize_t n;
  int ok = 1;

  while ((n = read(sfd, buf, sizeof(buf))) > 0) {
    ssize_t w = 0;
    while (w < n) {
      ssize_t r = write(dfd, buf + w, (size_t)(n - w));
      if (r <= 0) {
        ok = 0;
        break;
      }
      w += r;
    }
    if (!ok) break;
  }

  close(sfd);
  close(dfd);

  if (ok) LOGD("copy_file: '%s' -> '%s'", src, dst);
  else LOGE("copy_file: write error for '%s'", dst);

  return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers — real path resolution
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * resolve_dir_from_maps() - Find the real directory of a mapped library.
 *
 * Parses /proc/self/maps to locate the first mapping whose path contains
 * @libname, then strips the filename to return the containing directory.
 *
 * This is the only reliable method to obtain the container-remapped real
 * path after dlopen. Pre-dlopen approaches (dladdr on bridge lib, readlink
 * on /proc/self/fd) do not work in this container environment.
 *
 * @libname:  Filename to search for (e.g. "libfrida-gadget.so").
 * @out_dir:  Output buffer for the directory path (no trailing slash).
 * @sz:       Size of @out_dir buffer.
 * @return:   1 on success, 0 if not found or on error.
 */
static int resolve_dir_from_maps(const char * libname,
  char * out_dir,
  size_t sz) {
  FILE * f = fopen("/proc/self/maps", "r");
  if (!f) {
    LOGE("resolve_dir_from_maps: fopen failed: %s", strerror(errno));
    return 0;
  }

  char line[1024];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, libname)) continue;

    /*
     * /proc/self/maps line format:
     *   addr-addr perms offset dev inode [path]
     * The path is the last whitespace-delimited token.
     */
    char * path_start = NULL;
    char * tok = strtok(line, " \t\n");
    while (tok) {
      path_start = tok;
      tok = strtok(NULL, " \t\n");
    }

    if (!path_start || path_start[0] != '/') continue;

    strncpy(out_dir, path_start, sz - 1);
    out_dir[sz - 1] = '\0';

    /* Strip filename — keep directory only. */
    char * slash = strrchr(out_dir, '/');
    if (slash) * slash = '\0';

    LOGD("resolve_dir_from_maps: '%s' -> '%s'", libname, out_dir);
    found = 1;
    break;
  }

  fclose(f);

  if (!found)
    LOGW("resolve_dir_from_maps: '%s' not found in /proc/self/maps", libname);

  return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers — ART availability
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * art_loaded_from_maps() - Check whether libart.so is mapped into the process.
 *
 * Scans /proc/self/maps for a line containing "libart.so". This is the
 * container-safe way to detect ART: RTLD_NOLOAD only finds libraries
 * registered in the standard dynamic linker namespace, which does not
 * reliably include ART inside a container environment even when it is
 * actually mapped into the process.
 *
 * @out_path:  Optional buffer to receive the full real path of libart.so.
 *             Pass NULL if the path is not needed.
 * @sz:        Size of @out_path (ignored if @out_path is NULL).
 * @return:    1 if found, 0 otherwise.
 */
static int art_loaded_from_maps(char * out_path, size_t sz) {
  FILE * f = fopen("/proc/self/maps", "r");
  if (!f) return 0;

  char line[1024];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "libart.so")) continue;

    char * path = NULL;
    char * tok = strtok(line, " \t\n");
    while (tok) {
      path = tok;
      tok = strtok(NULL, " \t\n");
    }

    if (path && path[0] == '/') {
      if (out_path) {
        strncpy(out_path, path, sz - 1);
        out_path[sz - 1] = '\0';
      }
      found = 1;
      break;
    }
  }

  fclose(f);
  return found;
}

/**
 * wait_for_art() - Wait until libart.so is mapped into the process.
 *
 * Frida Gadget requires the Android Runtime to be present before it can
 * initialize. In container environments the bridge library may be loaded
 * before ART has been mapped into the process. This polls
 * /proc/self/maps (see art_loaded_from_maps) rather than using
 * dlopen(..., RTLD_NOLOAD), since the latter does not reliably detect
 * ART inside a container.
 *
 * @max_secs: Maximum seconds to wait.
 * @return:   1 if ART is available, 0 if timed out.
 */
static int wait_for_art(int max_secs) {
  char art_path[PATH_MAX] = {
    0
  };

  for (int i = 0; i < max_secs; i++) {
    if (art_loaded_from_maps(art_path, sizeof(art_path))) {
      LOGI("ART detected via maps: %s", art_path);
      return 1;
    }
    if (i == 0) LOGI("Waiting for ART...");
    sleep(1);
  }

  LOGE("ART not found in maps after %ds", max_secs);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers — config management
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * write_config_with_relative_script_path() - Write config with relative script path.
 *
 * Reads the source config JSON, rewrites the "path" field value to the
 * bare filename GADGET_SCRIPT_NAME (relative), and writes the result to
 * @dst_config.
 *
 * Frida Gadget resolves a relative "path" from the directory where gadget
 * is mapped in memory (real path). Absolute paths fail inside a container
 * because the container prepends its own root prefix, creating a double-
 * prefixed path that does not exist.
 *
 * If the source config has no "path" key (e.g. listen mode config), the
 * file is copied verbatim.
 *
 * @src_config:  Path to the source config file (logical path).
 * @dst_config:  Path to write the fixed config (real path).
 * @return:      1 on success, 0 on failure.
 */
static int write_config_with_relative_script_path(const char * src_config,
  const char * dst_config) {
  int fd = open(src_config, O_RDONLY);
  if (fd < 0) {
    LOGE("write_config: cannot open src '%s': %s", src_config, strerror(errno));
    return 0;
  }

  char buf[4096] = {
    0
  };
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0) {
    LOGE("write_config: read failed for '%s'", src_config);
    return 0;
  }
  buf[n] = '\0';

  LOGD("write_config: source: %.256s", buf);

  /* Locate "path" key. If absent, copy verbatim (e.g. listen mode). */
  char * path_key = strstr(buf, "\"path\"");
  if (!path_key) {
    LOGD("write_config: no path key, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  char * q1 = strchr(path_key + 6, '"');
  if (!q1) {
    LOGW("write_config: malformed path value, copying verbatim");
    return copy_file(src_config, dst_config);
  }
  q1++;

  char * q2 = strchr(q1, '"');
  if (!q2) {
    LOGW("write_config: unclosed path string, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  char new_cfg[4096] = {
    0
  };
  size_t pre = (size_t)(q1 - buf);
  size_t slen = strlen(GADGET_SCRIPT_NAME);
  size_t post = (size_t)(n - (q2 - buf));
  size_t total = pre + slen + post;

  if (total >= sizeof(new_cfg)) {
    LOGW("write_config: rewritten config too large, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  memcpy(new_cfg, buf, pre);
  memcpy(new_cfg + pre, GADGET_SCRIPT_NAME, slen);
  memcpy(new_cfg + pre + slen, q2, post);

  LOGD("write_config: rewritten: %.256s", new_cfg);

  int dfd = open(dst_config, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dfd < 0) {
    LOGE("write_config: cannot open dst '%s': %s", dst_config, strerror(errno));
    return 0;
  }

  ssize_t w = write(dfd, new_cfg, total);
  close(dfd);

  if (w != (ssize_t) total) {
    LOGE("write_config: partial write to '%s'", dst_config);
    return 0;
  }

  LOGD("write_config: written -> '%s'", dst_config);
  return 1;
}

/**
 * ensure_files_at_real_path() - Copy config and script to real gadget directory.
 *
 * Called after dlopen once the real gadget directory is known. Files are
 * only copied if they do not already exist at the real path, preserving
 * any manual updates the user may have made directly to the real path.
 *
 * Config "path" value is always rewritten to a relative filename regardless
 * of what the source config contains.
 *
 * @real_dir:        Real (container) gadget directory from /proc/self/maps.
 * @logical_config:  Logical path of the config file (user-maintained source).
 * @logical_script:  Logical path of the script file (user-maintained source).
 */
static void ensure_files_at_real_path(const char * real_dir,
  const char * logical_config,
    const char * logical_script) {
  char real_config[PATH_MAX];
  char real_script[PATH_MAX];

  snprintf(real_config, sizeof(real_config), "%s/%s", real_dir, GADGET_CONFIG_NAME);
  snprintf(real_script, sizeof(real_script), "%s/%s", real_dir, GADGET_SCRIPT_NAME);

  /* Config */
  if (access(real_config, F_OK) == 0) {
    LOGD("ensure_files: config already at real path, skipping");
  } else if (access(logical_config, F_OK) == 0) {
    if (write_config_with_relative_script_path(logical_config, real_config))
      LOGI("Config deployed to real path");
    else
      LOGE("Config deployment failed");
  } else {
    LOGW("Config not found at logical path '%s'", logical_config);
  }

  /* Script */
  if (access(real_script, F_OK) == 0) {
    LOGD("ensure_files: script already at real path, skipping");
  } else if (access(logical_script, F_OK) == 0) {
    if (copy_file(logical_script, real_script))
      LOGI("Script deployed to real path");
    else
      LOGE("Script deployment failed");
  } else {
    LOGD("ensure_files: no script at logical path (script mode not in use)");
  }

  LOGI("Real path status — config:[%s] script:[%s]",
    access(real_config, F_OK) == 0 ? "OK" : "MISSING",
    access(real_script, F_OK) == 0 ? "OK" : "MISSING");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers — Android integration
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * read_package_name() - Read the process package name from /proc/self/cmdline.
 *
 * Used as a fallback when JNI getFilesDir() fails. Some containers prefix
 * the cmdline entry with "pkg:" which is stripped before returning.
 *
 * @buf:  Output buffer for the package name.
 * @sz:   Size of @buf.
 */
static void read_package_name(char * buf, size_t sz) {
  buf[0] = '\0';
  FILE * f = fopen("/proc/self/cmdline", "rb");
  if (!f) {
    snprintf(buf, sz, "unknown");
    return;
  }

  size_t n = fread(buf, 1, sz - 1, f);
  fclose(f);

  if (!n) {
    snprintf(buf, sz, "unknown");
    return;
  }
  buf[n] = '\0';

  char * colon = strchr(buf, ':');
  if (colon) memmove(buf, colon + 1, strlen(colon + 1) + 1);
  if (!buf[0]) snprintf(buf, sz, "unknown");

  LOGD("read_package_name: '%s'", buf);
}

/**
 * get_files_dir_jni() - Obtain getFilesDir() path via JNI reflection.
 *
 * Calls ActivityThread.currentApplication().getFilesDir().getAbsolutePath()
 * through JNI. Retries up to 30 seconds waiting for the Application object
 * to be available during early process startup.
 *
 * @out_buf:  Output buffer for the files directory path.
 * @out_sz:   Size of @out_buf.
 * @return:   1 on success, 0 on failure.
 */
static int get_files_dir_jni(char * out_buf, size_t out_sz) {
  JavaVM * jvm = atomic_load_explicit( & g_jvm, memory_order_acquire);
  if (!jvm) {
    LOGW("get_files_dir_jni: g_jvm is NULL");
    return 0;
  }

  JNIEnv * env = NULL;
  int attached = 0;
  int result = 0;

  jint rc = ( * jvm) -> GetEnv(jvm, (void ** ) & env, JNI_VERSION_1_6);
  if (rc == JNI_EDETACHED) {
    if (( * jvm) -> AttachCurrentThread(jvm, & env, NULL) != JNI_OK) {
      LOGW("get_files_dir_jni: AttachCurrentThread failed");
      return 0;
    }
    attached = 1;
  } else if (rc != JNI_OK) {
    return 0;
  }

  jclass cls_at = NULL;
  jmethodID mid_ca = NULL;
  jobject app = NULL;
  jclass cls_ctx = NULL;
  jmethodID mid_gfd = NULL;
  jobject file = NULL;
  jclass cls_file = NULL;
  jmethodID mid_gap = NULL;
  jstring path_str = NULL;
  const char * chars = NULL;

  #define JNI_CLR() \
  do { \
    if (( * env) -> ExceptionCheck(env))( * env) -> ExceptionClear(env); \
  } while (0)

  cls_at = ( * env) -> FindClass(env, "android/app/ActivityThread");
  if (!cls_at) {
    JNI_CLR();
    goto jni_done;
  }

  mid_ca = ( * env) -> GetStaticMethodID(env, cls_at,
    "currentApplication", "()Landroid/app/Application;");
  if (!mid_ca) {
    JNI_CLR();
    goto jni_done;
  }

  for (int i = 0; i < 30; ++i) {
    app = ( * env) -> CallStaticObjectMethod(env, cls_at, mid_ca);
    JNI_CLR();
    if (app) break;
    if (i % 5 == 0)
      LOGD("get_files_dir_jni: waiting for Application (%d/30)...", i);
    sleep(1);
  }
  if (!app) {
    LOGW("get_files_dir_jni: Application still null after 30s");
    goto jni_done;
  }

  cls_ctx = ( * env) -> FindClass(env, "android/content/Context");
  if (!cls_ctx) {
    JNI_CLR();
    goto jni_done;
  }

  mid_gfd = ( * env) -> GetMethodID(env, cls_ctx, "getFilesDir", "()Ljava/io/File;");
  if (!mid_gfd) {
    JNI_CLR();
    goto jni_done;
  }

  file = ( * env) -> CallObjectMethod(env, app, mid_gfd);
  JNI_CLR();
  if (!file) goto jni_done;

  cls_file = ( * env) -> FindClass(env, "java/io/File");
  if (!cls_file) {
    JNI_CLR();
    goto jni_done;
  }

  mid_gap = ( * env) -> GetMethodID(env, cls_file,
    "getAbsolutePath", "()Ljava/lang/String;");
  if (!mid_gap) {
    JNI_CLR();
    goto jni_done;
  }

  path_str = (jstring)( * env) -> CallObjectMethod(env, file, mid_gap);
  JNI_CLR();

  if (path_str) {
    chars = ( * env) -> GetStringUTFChars(env, path_str, NULL);
    if (chars && chars[0]) {
      strncpy(out_buf, chars, out_sz - 1);
      out_buf[out_sz - 1] = '\0';
      result = 1;
      LOGD("get_files_dir_jni: '%s'", out_buf);
    }
    if (chars)( * env) -> ReleaseStringUTFChars(env, path_str, chars);
  }

  jni_done:
    if (path_str) (*env)->DeleteLocalRef(env, path_str);
    if (cls_file) (*env)->DeleteLocalRef(env, cls_file);
    if (file)     (*env)->DeleteLocalRef(env, file);
    if (cls_ctx)  (*env)->DeleteLocalRef(env, cls_ctx);
    if (app)      (*env)->DeleteLocalRef(env, app);
    if (cls_at)   (*env)->DeleteLocalRef(env, cls_at);
    if (attached) (*jvm)->DetachCurrentThread(jvm);

  return result;
  #undef JNI_CLR
}

/**
 * read_bridge_cfg() - Read the delay value from frida-bridge.cfg.
 *
 * The config file is a simple key=value text file. Example:
 *   delay=3
 *
 * Accepted range: 0-60 seconds. Falls back to DEFAULT_DELAY_SECS (0) if
 * the file is missing, unreadable, or contains an out-of-range value.
 *
 * @frida_dir:  Path to the frida subdirectory.
 * @return:     Delay in seconds.
 */
static int read_bridge_cfg(const char * frida_dir) {
  char cfg_path[PATH_MAX];
  snprintf(cfg_path, sizeof(cfg_path), "%s/%s", frida_dir, BRIDGE_CFG_FILE);

  int fd = open(cfg_path, O_RDONLY);
  if (fd < 0) {
    LOGD("read_bridge_cfg: not found, using default %ds", DEFAULT_DELAY_SECS);
    return DEFAULT_DELAY_SECS;
  }

  char buf[64] = {
    0
  };
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0) return DEFAULT_DELAY_SECS;
  buf[n] = '\0';

  char * p = strstr(buf, "delay=");
  if (p) {
    int v = atoi(p + 6);
    if (v >= 0 && v <= MAX_DELAY_SECS) {
      LOGD("read_bridge_cfg: delay=%ds", v);
      return v;
    }
  }

  LOGW("read_bridge_cfg: parse error, using default %ds", DEFAULT_DELAY_SECS);
  return DEFAULT_DELAY_SECS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Debug helpers (compiled in only with FRIDA_BRIDGE_DEBUG)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef FRIDA_BRIDGE_DEBUG
/**
 * dbg_log_gadget_maps() - Log all /proc/self/maps entries for gadget.
 */
static void dbg_log_gadget_maps(void) {
  FILE * f = fopen("/proc/self/maps", "r");
  if (!f) return;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, GADGET_LIB_NAME)) continue;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
    LOGD("maps: %s", line);
  }
  fclose(f);
}

/**
 * dbg_log_real_dir_contents() - Log files in the real gadget directory.
 */
static void dbg_log_real_dir_contents(const char * real_dir) {
  DIR * dr = opendir(real_dir);
  if (!dr) {
    LOGD("dbg_dir: opendir failed: %s", strerror(errno));
    return;
  }
  struct dirent * de;
  while ((de = readdir(dr)) != NULL) {
    if (de -> d_name[0] == '.') continue;
    char fpath[PATH_MAX];
    struct stat st;
    snprintf(fpath, sizeof(fpath), "%s/%s", real_dir, de -> d_name);
    stat(fpath, & st);
    LOGD("dbg_dir: %-40s  size=%-10lld  mode=%04o",
      de -> d_name, (long long) st.st_size, st.st_mode & 07777);
  }
  closedir(dr);
}
#else
static void dbg_log_gadget_maps(void) {}
static void dbg_log_real_dir_contents(const char * d) {
  (void) d;
}
#endif /* FRIDA_BRIDGE_DEBUG */

/* ═══════════════════════════════════════════════════════════════════════════
 * Main bridge thread
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * bridge_thread() - Main bridge logic, runs in a detached background thread.
 *
 * Sequence:
 *   1.  Wait for JavaVM to be set by JNI_OnLoad.
 *   2.  Resolve the logical files directory via JNI (package name fallback).
 *       JNI internally waits for Application to be ready.
 *   3.  Build logical paths for gadget, config, and script.
 *   4.  Read startup delay from bridge config.
 *   5.  Sleep for the configured delay (post-Application-ready).
 *   6.  Wait for ART (libart.so) to be present in the process.
 *       Frida Gadget requires ART to initialize. In container environments
 *       ART may not be loaded at the time the bridge starts.
 *   7.  dlopen gadget using the logical path (kernel remaps to real path).
 *   8.  Resolve real gadget directory from /proc/self/maps.
 *   9.  Ensure config and script are present at the real path.
 *       First launch: copies files. Subsequent launches: skips copy.
 *  10.  Log environment type (container vs non-container).
 */
static void * bridge_thread(void * arg) {
  (void) arg;
  LOGI("Bridge started");

  /* 1. Wait for JVM. */
  int waited = 0;
  while (atomic_load_explicit( & g_jvm, memory_order_acquire) == NULL &&
    waited++ < JVM_WAIT_SECS) {
    sleep(1);
  }
  if (atomic_load_explicit( & g_jvm, memory_order_acquire) == NULL) {
    LOGE("JavaVM unavailable after %ds, aborting", JVM_WAIT_SECS);
    return NULL;
  }

  /* 2. Resolve logical files directory.
   *    get_files_dir_jni() waits internally for Application to be ready. */
  char files_dir[PATH_MAX] = {
    0
  };
  if (!get_files_dir_jni(files_dir, sizeof(files_dir))) {
    char pkg[256] = {
      0
    };
    read_package_name(pkg, sizeof(pkg));
    if (strcmp(pkg, "unknown") == 0) {
      LOGE("Cannot determine files directory, aborting");
      return NULL;
    }
    snprintf(files_dir, sizeof(files_dir), "/data/data/%s/files", pkg);
    LOGW("JNI fallback files dir: %s", files_dir);
  }
  LOGI("Files dir: %s", files_dir);

  /* 3. Build logical paths. */
  char logical_frida[PATH_MAX];
  char logical_gadget[PATH_MAX];
  char logical_config[PATH_MAX];
  char logical_script[PATH_MAX];

  snprintf(logical_frida, sizeof(logical_frida), "%s/%s", files_dir, GADGET_SUBDIR);
  snprintf(logical_gadget, sizeof(logical_gadget), "%s/%s", logical_frida, GADGET_LIB_NAME);
  snprintf(logical_config, sizeof(logical_config), "%s/%s", logical_frida, GADGET_CONFIG_NAME);
  snprintf(logical_script, sizeof(logical_script), "%s/%s", logical_frida, GADGET_SCRIPT_NAME);

  if (access(logical_gadget, F_OK) != 0) {
    LOGE("Gadget not found at '%s', aborting", logical_gadget);
    return NULL;
  }

  /* 4. Read startup delay. */
  int delay = read_bridge_cfg(logical_frida);

  /* 5. Post-Application-ready delay.
   *
   * Placed after get_files_dir_jni() which already waits for Application.
   * This additional delay gives the app's own initialization (Activity,
   * Service, ContentProvider) more time before gadget hooks run.
   * Default is 0 — increase via frida-bridge.cfg if hooks miss early calls. */
  if (delay > 0) {
    LOGD("Post-init delay: %ds", delay);
    sleep(delay);
  }

  /* 6. Wait for ART.
   *
   * Frida Gadget requires libart.so to be present in the process before
   * dlopen. In container environments ART may load after the bridge
   * library. We poll with RTLD_NOLOAD (non-loading check) until ready. */
  if (!wait_for_art(ART_WAIT_SECS)) {
    LOGW("ART not detected — loading gadget anyway, may fail");
  }

  /* 7. Load gadget.
   *    Kernel container VFS remapping translates logical path to real path. */
  LOGD("dlopen: '%s'", logical_gadget);
  void * handle = dlopen(logical_gadget, RTLD_NOW | RTLD_GLOBAL);
  if (!handle) {
    LOGE("dlopen failed: %s", dlerror());
    return NULL;
  }
  LOGI("Gadget loaded");
  dbg_log_gadget_maps();

  /* 8. Resolve real gadget directory. */
  char real_dir[PATH_MAX] = {
    0
  };
  if (!resolve_dir_from_maps(GADGET_LIB_NAME, real_dir, sizeof(real_dir))) {
    LOGE("Cannot resolve real gadget directory from maps");
    return NULL;
  }
  LOGD("Real gadget dir: %s", real_dir);
  dbg_log_real_dir_contents(real_dir);

  /* 9. Ensure config and script at real path. */
  ensure_files_at_real_path(real_dir, logical_config, logical_script);

  /* 10. Report environment. */
  int in_container = (strcmp(real_dir, logical_frida) != 0);
  if (in_container)
    LOGI("Container environment — files synced to real path");
  else
    LOGI("Non-container environment");

  LOGI("Bridge done");
  return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Library entry points
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * lib_constructor() - Library constructor, called when .so is loaded.
 *
 * Spawns a detached background thread that performs the gadget loading
 * sequence. Using a thread avoids blocking the loader and allows waiting
 * for the JavaVM and Application object without stalling the process.
 */
__attribute__((constructor))
static void lib_constructor(void) {
  LOGI("FridaBridge initializing");

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init( & attr);
  pthread_attr_setdetachstate( & attr, PTHREAD_CREATE_DETACHED);

  if (pthread_create( & t, & attr, bridge_thread, NULL) != 0)
    LOGE("pthread_create failed: %s", strerror(errno));
  else
    LOGD("Bridge thread spawned");

  pthread_attr_destroy( & attr);
}

/**
 * JNI_OnLoad() - JNI entry point, called when the library is loaded by Java.
 *
 * Saves the JavaVM pointer for use by the bridge thread.
 *
 * @vm:       JavaVM pointer provided by the Android runtime.
 * @reserved: Unused.
 * @return:   Minimum required JNI version.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM * vm, void * reserved) {
  (void) reserved;
  atomic_store_explicit( & g_jvm, vm, memory_order_release);
  LOGD("JNI_OnLoad: JavaVM saved");
  return JNI_VERSION_1_6;
}