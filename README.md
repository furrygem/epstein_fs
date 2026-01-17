Look, i know most people don't really care about what's happening under the hood, but i've been spending a lot of time staring at `dmesg` logs lately. there's something kind of... honest about the kernel. it doesn't pretend to be anything it isn't.

anyways, here's a little thing i put together. it's called **epstein_fs** (im so funny and cool). it's a linux kernel module (tested on 6.12) that hooks `getdents64` via a kretprobe.

---

## # epstein_fs

if you're wondering what that actually means: `getdents64` is the syscall that tools like `ls` use to see directory entries. by jumping in there, the module can log or redact file names at the kernel boundary before the system even knows what hit it.

### core idea (the vibe)

think of `getdents64` as the "directory list stream." this module just sits there in the kernel, watching that stream. it decides if the caller looks interactive (like if there's a TTY or a shell parent), and then optionally scrubs some names with a block glyph before returning them.

it's like putting a tiny filter on the actual syscall data path, not just on the printed output. it's deeper than that.

### how it works

* **registers a kretprobe** on one of the `getdents64` symbols for arm64.
* **captures** the syscall buffer and size.
* **applies filters** to see who's asking:
* require a controlling TTY (`filter_require_tty`)
* require a parent shell name (`filter_parent_comm`)


* **optionally redacts** random slices of names using `█` based on:
* `redact_names`
* `redact_probability_percent`
* `redact_slice_min` / `redact_slice_max`


* **writes the modified buffer** back to userspace and updates the return size so everything stays (mostly) stable.

### build

```sh
make

```

### load / unload

if you want to try it out, it's just the usual stuff:

```sh
sudo insmod epstein_fs.ko
sudo rmmod epstein_fs

```

### tuning

you can edit these in `epstein_fs.c` to change how the chaos feels:

* `filter_require_tty` / `filter_parent_comm`
* `parent_comm_allowlist`
* `redact_names`
* `redact_probability_percent`
* `redact_slice_min` / `redact_slice_max`
* `protected_entries`

### notes

* `getdents64` is a syscall, so this is a real-deal kernel-level hook.
* redaction changes what userspace actually receives. if a program can't find a file because the name is half-blocked out... well, that's just how it goes sometimes.
