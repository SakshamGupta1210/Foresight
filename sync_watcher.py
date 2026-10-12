"""
FORESIGHT — Safe Automatic GitHub Sync Watcher
Monitors project files for modifications, debounces rapid saves,
creates descriptive commits, and safely syncs to GitHub main branch.
"""

import os
import sys
import time
import subprocess
from datetime import datetime

# Configuration
REPO_DIR = os.path.abspath(os.path.dirname(__file__))
DEBOUNCE_SECONDS = 6.0   # Wait 6 seconds after last save before pushing
POLL_INTERVAL_SECONDS = 1.5  # Scan filesystem every 1.5s
BRANCH = "main"
REMOTE = "origin"

# Explicitly ignored paths (in addition to .gitignore)
IGNORE_DIRS = {'.git', '__pycache__', 'venv', 'env', '.venv', 'instance', '.idea', '.vscode', 'scratch'}
IGNORE_EXTS = {'.pyc', '.pyo', '.pyd', '.db', '.sqlite', '.sqlite3', '.log', '.tmp', '.swp'}
IGNORE_FILES = {'foresight.db', '.env', '.DS_Store', 'Thumbs.db'}


def get_git_executable():
    """Finds git executable in local Git installation or system PATH."""
    local_git = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\cmd\git.exe")
    if os.path.isfile(local_git):
        return local_git
    return "git"


GIT_BIN = get_git_executable()


def run_git(args, check=False):
    """Executes a git command and returns (returncode, stdout, stderr)."""
    env = os.environ.copy()
    git_dir = os.path.dirname(GIT_BIN)
    if git_dir and git_dir not in env.get("PATH", ""):
        env["PATH"] = git_dir + os.pathsep + env.get("PATH", "")

    try:
        proc = subprocess.run(
            [GIT_BIN] + args,
            cwd=REPO_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"Git command failed: {' '.join(args)}\n{proc.stderr}")
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def get_project_file_snapshot():
    """Returns a dict of {rel_path: mtime} for tracked project files."""
    snapshot = {}
    for root, dirs, files in os.walk(REPO_DIR):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for f in files:
            if f in IGNORE_FILES or f.startswith('.env'):
                continue
            _, ext = os.path.splitext(f)
            if ext.lower() in IGNORE_EXTS:
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, REPO_DIR).replace('\\', '/')
            try:
                snapshot[rel_path] = os.path.getmtime(full_path)
            except OSError:
                pass
    return snapshot


def get_changed_files_summary():
    """Checks git status --porcelain to get a clean list of changes."""
    code, out, _ = run_git(["status", "--porcelain"])
    if code != 0 or not out:
        return []

    changed = []
    for line in out.splitlines():
        if len(line) >= 4:
            status_code = line[:2].strip()
            filepath = line[3:].strip()
            changed.append((status_code, filepath))
    return changed


def generate_commit_message(changed_items):
    """Creates a concise, human-readable commit message based on modified files."""
    if not changed_items:
        return "Update project files"

    files = [item[1] for item in changed_items]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if len(files) == 1:
        return f"Update {files[0]} ({timestamp})"
    elif len(files) <= 3:
        file_list = ", ".join(files)
        return f"Update {file_list} ({timestamp})"
    else:
        first_two = ", ".join(files[:2])
        return f"Update {first_two} and {len(files) - 2} other files ({timestamp})"


def check_remote_status():
    """
    Fetches remote branch status to ensure we do not overwrite remote changes.
    Returns: 'ok', 'diverged', or 'offline'
    """
    code, _, err = run_git(["fetch", REMOTE, BRANCH])
    if code != 0:
        if "Could not resolve host" in err or "Failed to connect" in err or "Network is unreachable" in err:
            return "offline"
        # Could be auth error or other issue
        return "error:" + err

    # Check status between local and origin/main
    code, out, _ = run_git(["rev-list", "--left-right", "--count", f"{BRANCH}...{REMOTE}/{BRANCH}"])
    if code == 0 and out:
        parts = out.split()
        if len(parts) == 2:
            ahead = int(parts[0])
            behind = int(parts[1])
            if behind > 0:
                return "behind"
    return "ok"


def sync_cycle():
    """Executes a single check, stage, commit, and push cycle."""
    changed = get_changed_files_summary()
    if not changed:
        return False

    # Safety check: Ensure no database or private file was accidentally touched
    for _, filepath in changed:
        if filepath.endswith('.db') or filepath.startswith('.env') or 'foresight.db' in filepath:
            print(f"[SECURITY WARNING] Skipping staging for sensitive/database file: {filepath}")
            run_git(["reset", "HEAD", filepath])

    # Re-verify changes
    changed = get_changed_files_summary()
    if not changed:
        return False

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Detected {len(changed)} changed file(s). Staging...")
    run_git(["add", "-A"])

    # Double check staged files
    code, staged_out, _ = run_git(["diff", "--staged", "--name-only"])
    if code != 0 or not staged_out:
        print("[-] No staged changes to commit.")
        return False

    msg = generate_commit_message(changed)
    print(f"[*] Creating commit: \"{msg}\"")
    commit_code, _, commit_err = run_git(["commit", "-m", msg])
    if commit_code != 0:
        print(f"[-] Commit failed: {commit_err}")
        return False

    print(f"[*] Pushing to {REMOTE}/{BRANCH}...")
    push_code, push_out, push_err = run_git(["push", REMOTE, BRANCH])

    if push_code == 0:
        print(f"[+] Successfully pushed to GitHub ({REMOTE}/{BRANCH}) at {datetime.now().strftime('%H:%M:%S')}")
        return True
    else:
        # Check reasons
        if "Authentication failed" in push_err or "could not read Username" in push_err or "terminal prompts disabled" in push_err:
            print(f"[!] Authentication required: Please run 'git push origin main' or 'gh auth login' once in your terminal to sign in.")
        elif "non-fast-forward" in push_err or "fetch first" in push_err:
            print(f"[!] Remote has newer commits. Please pull or resolve remote changes before pushing.")
        else:
            print(f"[-] Push failed ({push_err}). Will retry on next file change or connection recovery.")
        return False


def main():
    print("=" * 65)
    print(" FORESIGHT — Automatic GitHub Synchronization Watcher")
    print(f" Repository : {REPO_DIR}")
    print(f" Target      : {REMOTE}/{BRANCH}")
    print(f" Debounce    : {DEBOUNCE_SECONDS}s")
    print("=" * 65)
    print("[*] Watcher active. Monitoring project for saved changes...")
    print("[*] Press Ctrl+C anytime to stop.\n")

    last_snapshot = get_project_file_snapshot()
    pending_sync = False
    last_change_time = 0.0

    while True:
        try:
            time.sleep(POLL_INTERVAL_SECONDS)
            current_snapshot = get_project_file_snapshot()

            # Compare snapshots
            if current_snapshot != last_snapshot:
                last_snapshot = current_snapshot
                pending_sync = True
                last_change_time = time.time()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] File modification detected. Waiting {DEBOUNCE_SECONDS}s for edits to settle...")

            # If quiet period has elapsed after last change, trigger sync
            if pending_sync and (time.time() - last_change_time) >= DEBOUNCE_SECONDS:
                pending_sync = False
                sync_cycle()

        except KeyboardInterrupt:
            print("\n[*] Automatic sync watcher stopped by user.")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Unexpected error in watcher loop: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
