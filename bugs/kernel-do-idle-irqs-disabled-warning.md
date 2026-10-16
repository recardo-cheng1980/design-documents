# Kernel WARNING at `kernel/sched/idle.c:267` (`do_idle`) — root cause

- **Date:** 2026-10-16
- **Kernel:** `6.18.30-01953-g5086fd78561b-dirty` (linux-qcom, IQ-9075 EVK)
- **Source log:** `remote.dut:/cygdrive/c/putty_log/aiot_20261016143411.log` (UART, 4 boots)
- **Status:** root cause identified from source code; fix not yet implemented or verified on the DUT

## Symptom

Once per boot, between ~0.12 s and ~0.27 s. Original data (boot 4, UART log):

```
[    0.270071] Loading compiled-in X.509 certificates
[    0.273888] ------------[ cut here ]------------
[    0.273894] WARNING: CPU: 2 PID: 0 at /usr/src/kernel/kernel/sched/idle.c:267 do_idle+0x218/0x2c0
[    0.273912] Modules linked in:
[    0.273918] CPU: 2 UID: 0 PID: 0 Comm: swapper/2 Tainted: G        W           6.18.30-01953-g5086fd78561b-dirty #1 PREEMPT
[    0.273921] Tainted: [W]=WARN
[    0.273922] Hardware name: Qualcomm Technologies, Inc. Lemans EVK (DT)
[    0.273924] pstate: 404000c9 (nZcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[    0.273926] pc : do_idle+0x218/0x2c0
[    0.273928] lr : do_idle+0x15c/0x2c0
[    0.273930] sp : ffff80008020be30
[    0.273931] x29: ffff80008020be40 x28: 0000000000000000 x27: 0000000000000000
[    0.273933] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000002
[    0.273935] x23: ffff000084a2f080 x22: ffffda54a9cca000 x21: 0000000000000002
[    0.273937] x20: ffffda54a9ccac70 x19: ffff000ecfb3b238 x18: 0000000000000000
[    0.273939] x17: 000000040044ffff x16: 005000f2b5503510 x15: 0000000000000000
[    0.273941] x14: 0000000000000012 x13: 0000000000000001 x12: 0000000000000000
[    0.273943] x11: 071c71c71c71c71c x10: ffff000ecfb3b5ac x9 : ffffffffffffffff
[    0.273945] x8 : 0000000000000018 x7 : 0000000000000001 x6 : ffff000ecfb2d080
[    0.273946] x5 : ffffda54a9ccea50 x4 : 0000000000000000 x3 : ffff25ba25f44000
[    0.273948] x2 : ffffda54a8cb8840 x1 : 00000000fffffff0 x0 : 00000000000000c0
[    0.273951] Call trace:
[    0.273952]  do_idle+0x218/0x2c0 (P)
[    0.273956]  cpu_startup_entry+0x34/0x40
[    0.273959]  secondary_start_kernel+0x134/0x160
[    0.273963]  __secondary_switched+0xc0/0xc4
[    0.273967] ---[ end trace 0000000000000000 ]---
[    0.273985] Demotion targets for Node 0: null
```

This is a WARNING, not a kernel panic. The log contains no panic, Oops, BUG,
RCU stall, or hung task. The 3 reboots in the log are all normal systemd
shutdowns ending in `reboot: Restarting system`.

The warning comes from a patch Qualcomm added to the kernel. One line is
missing: when a CPU decides not to go idle, it returns without turning
interrupts back on.

## Cause

| Step | What happens | Code location |
|---|---|---|
| 1 | A CPU has nothing to do and gets ready to go idle. It turns interrupts off first, which is normal | `kernel/sched/idle.c` |
| 2 | Qualcomm's patch adds a check here: if another CPU has just sent a request (an IPI, a signal one CPU sends to another), skip idle and return right away | `drivers/cpuidle/cpuidle.c:225`, commit `3caa15b2812b` "FROMLIST: cpuidle: Deny idle entry when CPU already have IPI interrupt pending" |
| 3 | **This is the bug.** The normal exit turns interrupts back on at line 292. The new early return skips that line, so interrupts stay off | Lines 225–226: nothing turns interrupts back on before `return -EBUSY;` |
| 4 | Back in the caller, the kernel sees that idle is over but interrupts are still off. It prints this warning and turns them back on | `kernel/sched/idle.c:267` (`WARN_ON_ONCE(irqs_disabled())`) |

The offending code in `drivers/cpuidle/cpuidle.c` (`cpuidle_enter_state()`):

```c
	if (cpus_peek_for_pending_ipi(cpumask_of(dev->cpu)))
		return -EBUSY;          /* returns with IRQs still disabled */
	...
	if (!cpuidle_state_is_coupled(drv, index))
		local_irq_enable();     /* line 292 — skipped by the early return */
```

The registers in the log match this. `pstate` shows `daIF`, where the capital
I and F mean interrupts are off, and x0 = `0xc0` means the same thing.

## Taint information

The warning header shows `Tainted: G        W` and `Tainted: [W]=WARN`.

| Flag | Meaning | Why it is set here |
|---|---|---|
| `G` | Only GPL-compatible modules are loaded (no proprietary module yet) | Normal at this early stage of boot; no modules are loaded (`Modules linked in:` is empty) |
| `W` | A kernel WARNING has already been printed during this boot | Set by the **first** WARNING of the boot, not necessarily by this one |
| `-dirty` (in the version string) | Not a taint flag. The kernel was built from a source tree with uncommitted local changes | `git diff --stat` in the kernel source shows 28 changed files, plus some untracked files (MHI, stmmac, ath11k, wwan, DTS, …); none of them are in the cpuidle, scheduler, SMP, or RAS code |

Taint order per boot, from the UART log:

| Boot | First WARNING of the boot (sets `W`) | `idle.c:267` warning header |
|---|---|---|
| 1 | AEST `notifier.c:23` at 0.127 s (`Not tainted`) | 0.133 s, `Tainted: G W` |
| 2 | **`idle.c:267` itself** at 0.118 s | `Not tainted` |
| 3 | AEST `notifier.c:23` at 0.244 s (`Not tainted`) | 0.250 s, `Tainted: G W` |
| 4 | AEST `notifier.c:23` at 0.251 s (`Not tainted`) | 0.273 s, `Tainted: G W` (the excerpt above) |

Original taint value on the running DUT (2026-10-16, `adb shell`):

```
# cat /proc/sys/kernel/tainted
4608
```

So the `W` in the pasted excerpt was set by the earlier AEST notifier warning,
not by the `do_idle` warning. Both issues independently taint the kernel with
`W`; fixing only one of them will not clear the taint.

Taint on the running DUT (checked 2026-10-16): `/proc/sys/kernel/tainted` =
`4608` = `W` (512, a WARNING occurred) + `O` (4096, an out-of-tree module was
loaded later in boot). The `O` flag is unrelated to this issue.

## Why it shows up during boot

| Item | Explanation |
|---|---|
| Trigger | A CPU is just about to go idle at the moment another CPU sends it a request |
| Why boot makes this likely | Drivers often ask every CPU to do something at the same time during boot. For example, when the AEST driver loads, it has every CPU set up its error registers (`init_regs_on_cpu(true)` → `on_each_cpu()`) |
| What the log shows | In 3 of the 4 boots, the warning appears 5–25 ms after AEST loads. In the other boot it appears earlier, so another driver probably sent the request. AEST is one possible trigger, not where the bug is |
| Does it keep happening? | Yes, but it isn't printed again (`WARN_ON_ONCE`). Each time, the kernel turns interrupts back on by itself |

## Impact

| Item | Assessment |
|---|---|
| Crash? | No. The kernel fixes it on its own |
| Functionality | Not affected |
| Performance | Interrupts come back slightly late; too small to matter |
| Audits and tests | The boot log contains a WARNING and the kernel is marked tainted (`Tainted: W`), so it is easy to mistake for a crash |

## Fix options (suggested, not done yet)

| Option | Description |
|---|---|
| A (recommended) | Move the check into `call_cpuidle()` in `kernel/sched/idle.c`, next to the existing `current_clr_polling_and_test()` check. That code already turns interrupts back on before it returns `-EBUSY` |
| B | Keep the check where it is and turn interrupts back on before `return -EBUSY`. The function is `noinstr`, which limits what it can call, so this needs care |
| C | Remove the patch for now. The warning goes away, but so does the speed-up Qualcomm claims for it (25–30% higher glmark2 scores) |

The patch is tagged FROMLIST, which means it is still under review by the
Linux community
(<https://lore.kernel.org/r/20260403-cpuidle_ipi-v2-1-b3e44b032e2c@oss.qualcomm.com>).
Report the bug to Qualcomm, and check whether a newer version of the patch
already fixes it.

## Next steps

1. Write the plan doc and the test artifact (project Rules 8 and 10).
2. Add the fix as a kernel patch in `meta-wnc`.
3. Rebuild, flash, and reboot the DUT several times; confirm the
   `idle.c:267` warning no longer appears.

## Other warnings in the same log (not this issue)

| Message | Cause | Impact |
|---|---|---|
| `notifier.c:23` — `aest_cpu_pm_notify already registered` (2× per boot) | Qualcomm commit `0132f7bc9b90` "WORKAROUND: Move CPU PM notifier registration to Probe" registers the notifier in every `aest_device_probe()`; the device tree has 3 AEST nodes, so the 2nd and 3rd registrations are rejected | Harmless; fix by registering once |
| `pin GPIO_62 already requested by ac14000.cci` (repeats about every 30 s) | GPIO 62 is the CCI1 camera I2C pin, already owned by the camera driver; some process keeps trying to claim it | Log spam only; the requesting process has not been identified yet |
