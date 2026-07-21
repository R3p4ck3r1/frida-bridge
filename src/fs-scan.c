/*
 * fs-scan.c
 *
 * Filesystem-based target discovery.
 *
 * Some multi-app / clone-app containers (common on Android 10/11 OEM ROMs)
 * do NOT swap the in-process Application object returned by
 * ActivityThread.currentApplication() when running a cloned target app.
 * Instead they keep their own real on-disk data tree — typically mirroring
 * the standard Android layout — under their own app-owned storage, e.g.:
 *
 *   <container_root>/.../data/user/0/<target_pkg>/files/frida
 *   <container_root>/.../data/user/999/<target_pkg>/files/frida
 *
 * In that architecture, get_files_dir_jni()'s Application-polling approach
 * can never see the target: currentApplication() keeps returning the
 * container's own Application, so the payload marker (GADGET_SUBDIR) is
 * never found via JNI reflection.
 *
 * This module provides a fallback: recursively scan the container's own
 * real storage tree (rooted at its own getFilesDir(), which the process
 * already owns per the security model in README.md) for a "frida" payload
 * directory sitting directly under a "files" directory, regardless of how
 * many "data/user/<id>/<pkg>" levels of nesting the container uses.
 *
 * This never leaves the process's own storage tree, never follows symlinks,
 * and is depth/breadth bounded to keep runtime and memory use predictable.
 */

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "debug-logging.h"
#include "frida-bridge.h"

/* Bounds to keep the scan fast and safe even on a cluttered real filesystem. */
#define FS_SCAN_MAX_DEPTH   10
#define FS_SCAN_MAX_VISITED 20000

struct scan_state {
  char   found_files_dir[PATH_MAX];
  int    found;
  long   visited;
};

/**
 * scan_dir_recursive - Depth-first search for a "files/frida" payload dir.
 *
 * @dir:    Current directory to inspect (must be a real, non-symlink path).
 * @depth:  Current recursion depth.
 * @st:     Shared scan state (result + bookkeeping).
 */
static void scan_dir_recursive(const char *dir, int depth, struct scan_state *st) {
  if (st->found || depth > FS_SCAN_MAX_DEPTH || st->visited > FS_SCAN_MAX_VISITED)
    return;

  DIR *dp = opendir(dir);
  if (!dp) return;

  struct dirent *de;
  while ((de = readdir(dp)) != NULL) {
    if (st->found || st->visited > FS_SCAN_MAX_VISITED) break;
    if (de->d_name[0] == '.') continue; /* skip ".", "..", hidden dirs */

    char child[PATH_MAX];
    int n = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
    if (n <= 0 || (size_t)n >= sizeof(child)) continue;

    struct stat st_buf;
    /* lstat (not stat) so symlinks are never followed — stay inside the
     * app's own real storage tree, never escape via a crafted link. */
    if (lstat(child, &st_buf) != 0) continue;
    if (!S_ISDIR(st_buf.st_mode)) continue;

    st->visited++;

    /* Is this child itself the payload marker directory (GADGET_SUBDIR),
     * with its parent named "files" (i.e. this looks like
     * <...>/files/<GADGET_SUBDIR>) -- AND does it actually contain the
     * configured gadget library file? A directory match alone isn't
     * enough: a stale/leftover subdirectory from a previous config (e.g.
     * left over after renaming GADGET_SUBDIR/GADGET_LIB_NAME) must never
     * be mistaken for a valid target. */
    if (strcmp(de->d_name, GADGET_SUBDIR) == 0) {
      const char *base = strrchr(dir, '/');
      base = base ? base + 1 : dir;
      if (strcmp(base, "files") == 0) {
        char gadget_path[PATH_MAX];
        struct stat gadget_st;
        int n2 = snprintf(gadget_path, sizeof(gadget_path), "%s/%s",
                           child, GADGET_LIB_NAME);
        if (n2 > 0 && (size_t)n2 < sizeof(gadget_path) &&
            stat(gadget_path, &gadget_st) == 0 && S_ISREG(gadget_st.st_mode)) {
          strncpy(st->found_files_dir, dir, sizeof(st->found_files_dir) - 1);
          st->found_files_dir[sizeof(st->found_files_dir) - 1] = '\0';
          st->found = 1;
          LOGI("scan_dir_recursive: payload found under '%s'", dir);
          closedir(dp);
          return;
        } else {
          LOGD("scan_dir_recursive: '%s' exists but gadget file missing, "
               "skipping stale/incomplete candidate", child);
        }
      }
    }

    scan_dir_recursive(child, depth + 1, st);
  }

  closedir(dp);
}

/**
 * find_target_via_fs_scan - Fallback target discovery via filesystem scan.
 *
 * Walks the tree rooted at @host_files_dir (the calling process's own
 * getFilesDir(), always owned/readable by this process) looking for any
 * "<...>/files/frida" directory. Intended as a fallback for containers
 * that never swap the in-process Application object, so the JNI-based
 * get_files_dir_jni() polling approach can't observe the target's
 * directory directly.
 *
 * @host_files_dir:  The current process's own real files directory,
 *                    e.g. "/data/user/0/com.waxmoon.ma.gp/files".
 * @out_buf:          Output buffer to receive the matched files directory
 *                    (the "files" dir, i.e. parent of the "frida" payload).
 * @out_sz:           Size of @out_buf.
 * @return:           1 if a payload directory was found, 0 otherwise.
 */
int find_target_via_fs_scan(const char *host_files_dir, char *out_buf, size_t out_sz) {
  if (!host_files_dir || !out_buf || !out_sz) return 0;

  /* Search from the app's own root (one level above "files"), since the
   * container typically stores per-clone data as sibling/nested trees
   * next to its own files dir, not necessarily inside it. */
  char root[PATH_MAX];
  strncpy(root, host_files_dir, sizeof(root) - 1);
  root[sizeof(root) - 1] = '\0';

  char *slash = strrchr(root, '/');
  if (slash && strcmp(slash, "/files") == 0)
    *slash = '\0';

  LOGD("find_target_via_fs_scan: scanning from '%s'", root);

  struct scan_state st = {0};
  scan_dir_recursive(root, 0, &st);

  if (!st.found) {
    LOGW("find_target_via_fs_scan: no 'files/frida' payload found under '%s' "
         "(visited %ld directories)", root, st.visited);
    return 0;
  }

  strncpy(out_buf, st.found_files_dir, out_sz - 1);
  out_buf[out_sz - 1] = '\0';
  return 1;
}
