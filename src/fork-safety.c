/*
 * fork-safety.c
 *
 * Fork-safety mechanisms and idempotent worker thread spawning.
 *
 * When a process forks, threads do not survive in the child process;
 * only the calling thread continues. This module implements handlers
 * to reset bridge state post-fork and respawn the worker thread in
 * the child process, ensuring each process initializes independently.
 */

#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "frida-bridge.h"
#include "debug-logging.h"

/**
 * Forward declaration of ensure_bridge_started, defined later in this file.
 * Called from on_fork_child().
 */
void ensure_bridge_started(void);

/* Forward declaration of bridge_thread (defined in frida-bridge.c). */
extern void *bridge_thread(void *arg);

/* ═══════════════════════════════════════════════════════════════════════════
 * Fork Handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * on_fork_prepare - Called in parent process before fork().
 *
 * Acquires the bridge lock to ensure no worker thread is being spawned
 * at the moment of fork. This prevents inconsistent state in the child.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_prepare(void) {
  pthread_mutex_lock(&g_bridge_lock);
}

/**
 * on_fork_parent - Called in parent process after fork().
 *
 * Releases the bridge lock so the parent process can continue normally.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_parent(void) {
  pthread_mutex_unlock(&g_bridge_lock);
}

/**
 * on_fork_child - Called in child process after fork().
 *
 * Resets bridge state ONLY. Deliberately does NOT spawn a new worker
 * thread here.
 *
 * WHY NOT RESPAWN DIRECTLY HERE:
 * Calling ensure_bridge_started() (which calls pthread_create(), and
 * transitively bridge_thread()'s malloc-using calls: snprintf, fopen,
 * opendir/readdir, etc.) directly inside a pthread_atfork "child" handler
 * is a well-known deadlock hazard. fork() only duplicates the calling
 * thread; if some OTHER thread in the parent held an internal libc/
 * malloc-arena/dynamic-linker lock at the exact instant of fork(), that
 * lock is copied into the child already locked, with no thread left
 * alive to ever unlock it. The moment this handler (or anything it
 * calls) touches malloc(), the single surviving thread in the child
 * hangs forever.
 *
 * This is especially dangerous because our library is loaded process-
 * wide, so pthread_atfork() fires for EVERY fork() call anywhere in the
 * process -- including forks made by completely unrelated subsystems
 * (e.g. a crash-monitoring/watchdog library forking its own helper
 * process), not just app-cloning forks. A hang in one of those unrelated
 * forked children can manifest as an ANR / service-execution timeout
 * elsewhere in the app, with no obvious link back to this library.
 *
 * Respawning is instead left entirely to JNI_OnLoad(), which already
 * detects a new/changed JavaVM per cloned app instance (confirmed by
 * "JavaVM changed" log lines occurring once per clone) and calls
 * ensure_bridge_started() from a normal JNI callback context -- safe,
 * because it is not running inside fork()'s lock-inheritance danger
 * zone.
 *
 * In the child process:
 *   - The worker thread from the parent is GONE (threads don't survive fork).
 *   - The atomic flags from parent are inherited as stale values.
 *   - The JavaVM pointer (g_jvm) is still valid (inherited memory), but a
 *     new one will be delivered via JNI_OnLoad if/when this child becomes
 *     a real, distinct Android app process.
 *   - The mutex is in an undefined lock state and must be unlocked here.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_child(void) {
  /* Reset the started flag so a future, safely-triggered spawn can proceed. */
  g_bridge_started = 0;

  /* Unlock the mutex (it's in unknown state post-fork; this initializes it).
   * pthread_mutex_unlock() on our own never-contended-in-child mutex is the
   * only operation performed here -- deliberately nothing else. */
  pthread_mutex_unlock(&g_bridge_lock);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Idempotent Worker Spawning
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * ensure_bridge_started - Idempotently spawn the bridge worker thread.
 *
 * This function is called from multiple places:
 *   - lib_constructor() (when .so is loaded)
 *   - JNI_OnLoad() (fallback, if constructor's spawn failed)
 *   - on_fork_child() (after fork, to respawn in child)
 *
 * Uses atomic compare-and-swap to ensure only the FIRST caller succeeds
 * in spawning the worker thread. Subsequent calls are no-ops.
 *
 * If pthread_create() fails:
 *   - The flag is reset to allow retry.
 *   - An error is logged, but the process continues.
 *   - JNI_OnLoad() may retry on the next trigger.
 *
 * Protection: Holds g_bridge_lock during the actual pthread_create(),
 * preventing races with fork().
 */
void ensure_bridge_started(void) {
  /*
   * Atomic compare-and-swap: if g_bridge_started == 0, set to 1 and proceed.
   * Otherwise, another thread/call already triggered, so just return.
   */
  // int expected = 0;
  if (__sync_bool_compare_and_swap(&g_bridge_started, 0, 1) == 0) {
    /* Already started by another caller. */
    return;
  }

  /* Acquire lock to protect pthread_create() against fork(). */
  pthread_mutex_lock(&g_bridge_lock);

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  if (pthread_create(&t, &attr, bridge_thread, NULL) != 0) {
    LOGE("ensure_bridge_started: pthread_create failed: %s", strerror(errno));
    /* Reset flag to allow retry later. */
    g_bridge_started = 0;
  } else {
    LOGD("ensure_bridge_started: worker thread spawned successfully");
  }

  pthread_attr_destroy(&attr);
  pthread_mutex_unlock(&g_bridge_lock);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Fork Handler Registration
 *
 * Exposed as a non-static function so lib_constructor() can call it.
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * register_fork_handlers - Register fork-safety handlers.
 *
 * Installs the prepare/parent/child handlers via pthread_atfork().
 * Should be called once during library initialization (from lib_constructor).
 *
 * This MUST be called before any threads are spawned, to ensure
 * the fork handlers are registered in the process.
 */
void register_fork_handlers(void) {
  if (pthread_atfork(on_fork_prepare, on_fork_parent, on_fork_child) != 0) {
    LOGW("register_fork_handlers: pthread_atfork failed (may be in child process)");
  } else {
    LOGD("register_fork_handlers: fork handlers registered successfully");
  }
}
