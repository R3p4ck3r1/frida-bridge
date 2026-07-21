/*
 * container-path.c
 *
 * Container filesystem path resolution and ART availability detection.
 *
 * In container environments, Android's logical paths (returned by APIs like
 * getFilesDir()) differ from the real paths where files are actually mapped
 * in the process memory. This module provides utilities to resolve real paths
 * and detect when the Android Runtime is ready for gadget initialization.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "debug-logging.h"
#include "frida-bridge.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Real Path Resolution
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * resolve_dir_from_maps - Find the real directory of a mapped library.
 *
 * Parses /proc/self/maps to locate the first mapping containing @libname,
 * then extracts the directory path (strips the filename).
 *
 * This is the only reliable method to obtain container-remapped real paths
 * after dlopen(). Pre-dlopen approaches (dladdr, readlink on /proc/self/fd)
 * fail in container environments due to path remapping.
 *
 * @libname:  Library filename to search for (e.g., "libfrida-gadget.so").
 * @out_dir:  Output buffer for the directory path (no trailing slash).
 * @sz:       Size of @out_dir buffer.
 * @return:   1 on success, 0 if not found or on error.
 */
int resolve_dir_from_maps(const char *libname, char *out_dir, size_t sz) {
  if (!libname || !out_dir || !sz) return 0;

  FILE *f = fopen("/proc/self/maps", "r");
  if (!f) {
    LOGE("resolve_dir_from_maps: fopen failed");
    return 0;
  }

  char line[1024];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, libname)) continue;

    /*
     * /proc/self/maps line format:
     *   addr-addr perms offset dev inode [path]
     *
     * The path is the last whitespace-delimited token on the line.
     * We tokenize and keep the last non-null token.
     */
    char *path_start = NULL;
    char *tok = strtok(line, " \t\n");
    while (tok) {
      path_start = tok;
      tok = strtok(NULL, " \t\n");
    }

    if (!path_start || path_start[0] != '/') continue;

    /* Copy path and strip filename to get directory. */
    strncpy(out_dir, path_start, sz - 1);
    out_dir[sz - 1] = '\0';

    char *slash = strrchr(out_dir, '/');
    if (slash) *slash = '\0';

    LOGD("resolve_dir_from_maps: found '%s' -> directory '%s'", libname, out_dir);
    found = 1;
    break;
  }

  fclose(f);

  if (!found)
    LOGW("resolve_dir_from_maps: '%s' not found in /proc/self/maps", libname);

  return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ART Availability Detection
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * art_loaded_from_maps - Check whether libart.so is mapped into the process.
 *
 * Scans /proc/self/maps for any line containing "libart.so". This is the
 * container-safe way to detect ART; dlopen(RTLD_NOLOAD) is unreliable in
 * container environments even when ART is actually mapped into the process.
 *
 * @out_path:  Optional buffer to receive the full path of libart.so.
 *             Pass NULL if the path is not needed.
 * @sz:        Size of @out_path (ignored if @out_path is NULL).
 * @return:    1 if found and loaded, 0 otherwise.
 */
int art_loaded_from_maps(char *out_path, size_t sz) {
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f) return 0;

  char line[1024];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "libart.so")) continue;

    /* Extract the path token (last token on the line). */
    char *path = NULL;
    char *tok = strtok(line, " \t\n");
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
 * wait_for_art - Wait until libart.so is mapped into the process.
 *
 * Frida Gadget requires the Android Runtime to be present before it can
 * initialize. In container environments, ART may load after the bridge
 * library is loaded. This function polls /proc/self/maps at 1-second
 * intervals until ART is detected or timeout is reached.
 *
 * @max_secs:  Maximum seconds to wait for ART to become available.
 * @return:    1 if ART is detected and available, 0 if timeout reached.
 */
int wait_for_art(int max_secs) {
  char art_path[PATH_MAX] = {0};

  for (int i = 0; i < max_secs; i++) {
    if (art_loaded_from_maps(art_path, sizeof(art_path))) {
      LOGI("ART detected via /proc/self/maps: %s", art_path);
      return 1;
    }
    if (i == 0)
      LOGI("Waiting for ART to be loaded into process...");
    sleep(1);
  }

  LOGE("ART not found in /proc/self/maps after %d seconds", max_secs);
  return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Package Name Resolution
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * read_package_name - Read the process package name from /proc/self/cmdline.
 *
 * Reads the process command line and extracts the package name.
 * Used as a fallback when JNI-based file directory detection fails.
 *
 * Some container frameworks prefix the cmdline with "pkg:" which is stripped
 * before returning the package name.
 *
 * @buf:  Output buffer for the package name.
 * @sz:   Size of @buf. If package name doesn't fit, "unknown" is returned.
 */
void read_package_name(char *buf, size_t sz) {
  if (!buf || !sz) return;

  buf[0] = '\0';

  FILE *f = fopen("/proc/self/cmdline", "rb");
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

  /* Strip leading "pkg:" prefix if present. */
  char *colon = strchr(buf, ':');
  if (colon) {
    memmove(buf, colon + 1, strlen(colon + 1) + 1);
  }

  if (!buf[0])
    snprintf(buf, sz, "unknown");

  LOGD("read_package_name: extracted '%s'", buf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Target Application Readiness Check
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * is_target_app_ready - Check if a candidate Application has the expected payload.
 *
 * The definitive marker for a valid target is the presence of the actual
 * gadget library file (GADGET_LIB_NAME) inside the gadget subdirectory
 * (GADGET_SUBDIR) in the candidate's files directory. Both names are
 * read from frida-bridge.h so renaming them (e.g. to avoid signature-based
 * detection) only requires editing that one header.
 *
 * We deliberately check for the gadget *file*, not just the subdirectory:
 * a stale/leftover subdirectory from a previous config (e.g. left over
 * after renaming GADGET_SUBDIR) must never be mistaken for a valid target.
 *
 * This approach is package-agnostic: it does not hardcode package names or
 * rely on application order. The user explicitly deploys the gadget
 * subdirectory only in the target app's files directory, making the
 * gadget file's presence the definitive marker of a valid target.
 *
 * @files_dir:  Path to the candidate application's files directory.
 * @return:     1 if the gadget file is present as a regular file,
 *              0 if absent or of the wrong type.
 */
int is_target_app_ready(const char *files_dir) {
  if (!files_dir) return 0;

  char probe_path[PATH_MAX];
  struct stat st;

  snprintf(probe_path, sizeof(probe_path), "%s/%s/%s",
           files_dir, GADGET_SUBDIR, GADGET_LIB_NAME);
  int exists = (stat(probe_path, &st) == 0 && S_ISREG(st.st_mode));

  LOGD("is_target_app_ready: checking '%s' -> %s", probe_path,
       exists ? "PAYLOAD_FOUND" : "NO_PAYLOAD");

  return exists;
}
