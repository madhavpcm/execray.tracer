import os
import sys
import time

def main():
    """
    A test program to generate specific syscalls for an eBPF tracer to capture.
    """
    pid = os.getpid()
    print("--- Python Test Program Started ---")
    print(f"My PID is: {pid}")
    print("Start the eBPF tracer in another terminal, passing it my PID.")
    input("Once the tracer is running, press Enter in this window to continue...")

    # --- 1. Trigger an openat syscall equivalent ---
    # os.open() maps directly to the openat syscall on modern Linux.
    print("Step 1: Performing open syscall...")
    path = "/etc/hostname"  # A common, readable file.
    try:
        # os.open is a low-level call, closer to the syscall than open().
        fd = os.open(path, os.O_RDONLY)
        print(f"  -> open successful for '{path}', fd: {fd}")
        os.close(fd)
    except OSError as e:
        print(f"  -> open failed: {e}")

    time.sleep(1)

    # --- 2. Trigger a write syscall ---
    print("Step 2: Performing write syscall...")
    message = b"This is a test write from the Python test program.\n"
    try:
        # os.write() calls the write syscall on a file descriptor.
        # 1 corresponds to stdout.
        os.write(1, message)
        print("  -> write successful.")
    except OSError as e:
        print(f"  -> write failed: {e}")

    time.sleep(1)

    # --- 3. Trigger an execve syscall ---
    print("Step 3: Performing execve syscall to run '/bin/echo'...")
    print("This program will now be replaced by '/bin/echo'.")

    # Arguments for the new program. The first element is the program path.
    args = ["/bin/echo", "Hello", "from", "Python", "execve!"]
    
    try:
        # os.execve replaces the current process with the new one.
        os.execve(args[0], args, os.environ)
    except OSError as e:
        # This line will only be reached if execve fails.
        print(f"  -> execve failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()