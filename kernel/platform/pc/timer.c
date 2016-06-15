// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2009 Corey Tabaka
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <sys/types.h>

#include <assert.h>
#include <debug.h>
#include <err.h>
#include <reg.h>
#include <trace.h>

#include <arch/x86.h>
#include <arch/x86/apic.h>
#include <arch/x86/feature.h>
#include <lk/init.h>
#include <kernel/thread.h>
#include <kernel/spinlock.h>
#include <platform.h>
#include <dev/interrupt.h>
#include <platform/console.h>
#include <platform/timer.h>
#include <platform/pc.h>
#include "platform_p.h"

// Current timer scheme:
// The PIT is used to calibrate the local APIC timers initially.
// Afterwards, it is only used for maintaining wall time.
//
// The local APICs are responsible for handling timer callbacks
// sent from the scheduler.

static platform_timer_callback t_callback[SMP_MAX_CPUS] = {NULL};
static void *callback_arg[SMP_MAX_CPUS] = {NULL};

// PIT time accounting info
static uint64_t next_trigger_time;
static uint64_t next_trigger_delta;
static uint64_t ticks_per_ms;
static uint64_t timer_delta_time;
static volatile uint64_t timer_current_time;
static uint16_t pit_divisor;

// Whether or not we have an Invariant TSC (controls whether we use the PIT or
// not after initialization).
static bool invariant_tsc;

// APIC timer calibration values
static volatile uint32_t apic_ticks_per_ms = 0;
static uint8_t apic_divisor = 0;

// TSC timer calibration values
static uint64_t tsc_ticks_per_ms;

#define INTERNAL_FREQ 1193182ULL
#define INTERNAL_FREQ_3X 3579546ULL

/* Maximum amount of time that can be program on the timer to schedule the next
 *  interrupt, in miliseconds */
#define MAX_TIMER_INTERVAL 55

#define LOCAL_TRACE 0

lk_time_t current_time(void)
{
    lk_time_t time;

    if (invariant_tsc) {
        uint64_t tsc = rdtsc();
        time = tsc / tsc_ticks_per_ms;
    } else {
        // XXX slight race
        time = (lk_time_t) (timer_current_time >> 32);
    }

    return time;
}

lk_bigtime_t current_time_hires(void)
{
    lk_bigtime_t time;

    if (invariant_tsc) {
        uint64_t tsc = rdtsc();
        time = tsc / (tsc_ticks_per_ms / 1000);
    } else {
        // XXX slight race
        time = (lk_bigtime_t) ((timer_current_time >> 22) * 1000) >> 10;
    }

    return time;
}

// The PIT timer will keep track of wall time if we aren't using the TSC
static enum handler_return pit_timer_tick(void *arg)
{
    timer_current_time += timer_delta_time;
    return INT_NO_RESCHEDULE;
}

// The APIC timers will call this when they fire
enum handler_return platform_handle_timer_tick(void) {
    DEBUG_ASSERT(arch_ints_disabled());
    uint cpu = arch_curr_cpu_num();

    lk_time_t time = current_time();
    //lk_bigtime_t btime = current_time_hires();
    //printf_xy(71, 0, WHITE, "%08u", (uint32_t) time);
    //printf_xy(63, 1, WHITE, "%016llu", (uint64_t) btime);

    if (t_callback[cpu] && timer_current_time >= next_trigger_time) {
        lk_time_t delta = timer_current_time - next_trigger_time;
        next_trigger_time = timer_current_time + next_trigger_delta - delta;

        return t_callback[cpu](callback_arg[cpu], time);
    } else {
        return INT_NO_RESCHEDULE;
    }
}

static void set_pit_frequency(uint32_t frequency)
{
    uint32_t count, remainder;

    /* figure out the correct pit_divisor for the desired frequency */
    if (frequency <= 18) {
        count = 0xffff;
    } else if (frequency >= INTERNAL_FREQ) {
        count = 1;
    } else {
        count = INTERNAL_FREQ_3X / frequency;
        remainder = INTERNAL_FREQ_3X % frequency;

        if (remainder >= INTERNAL_FREQ_3X / 2) {
            count += 1;
        }

        count /= 3;
        remainder = count % 3;

        if (remainder >= 1) {
            count += 1;
        }
    }

    pit_divisor = count & 0xffff;

    /*
     * funky math that i don't feel like explaining. essentially 32.32 fixed
     * point representation of the configured timer delta.
     */
    timer_delta_time = (3685982306ULL * count) >> 10;

    //dprintf(DEBUG, "set_pit_frequency: dt=%016llx\n", timer_delta_time);
    //dprintf(DEBUG, "set_pit_frequency: pit_divisor=%04x\n", pit_divisor);

    /*
     * setup the Programmable Interval Timer
     * timer 0, mode 2, binary counter, LSB followed by MSB
     */
    outp(I8253_CONTROL_REG, 0x34);
    outp(I8253_DATA_REG, pit_divisor & 0xff); // LSB
    outp(I8253_DATA_REG, pit_divisor >> 8); // MSB
}

static void calibrate_apic_timer(void)
{
    ASSERT(arch_ints_disabled());
    ASSERT(ticks_per_ms <= 0xffff);

    apic_divisor = 1;
    while (apic_divisor != 0) {
        uint32_t best_time = UINT32_MAX;
        for (int tries = 0; tries < 3; ++tries) {
            // Make the PIT run for 1ms
            uint16_t init_pic_count = ticks_per_ms;
            // Program PIT in the software strobe configuration, this makes
            // it just count down.  When it hits 0, it will wrap around and
            // keep counting, so we need to watch for overflow below.
            outp(I8253_CONTROL_REG, 0x38);
            outp(I8253_DATA_REG, init_pic_count & 0xff); // LSB
            outp(I8253_DATA_REG, init_pic_count >> 8); // MSB

            // Setup APIC timer to count down with interrupt masked
            status_t status = apic_timer_set_oneshot(
                    UINT32_MAX,
                    apic_divisor,
                    true);
            ASSERT(status == NO_ERROR);

            uint16_t count = 0;
            do {
                // Latch the count for channel 0 (does not pause the actual
                // count)
                outp(I8253_CONTROL_REG, 0x00);
                count = inp(I8253_DATA_REG);
                count |= inp(I8253_DATA_REG) << 8;
            } while (count <= init_pic_count && count != 0);

            uint32_t apic_ticks = UINT32_MAX - apic_timer_current_count();
            if (apic_ticks < best_time) {
                best_time = apic_ticks;
            }
            LTRACEF("Calibration trial %d found %u ticks/ms\n",
                    tries, apic_ticks);
        }

        // If the APIC ran out of time every time, try again with a higher
        // divisor
        if (best_time == UINT32_MAX) {
            apic_divisor *= 2;
            continue;
        }

        apic_ticks_per_ms = best_time;
        break;
    }
    ASSERT(apic_divisor != 0);

    LTRACEF("APIC timer calibrated: %u ticks/ms, %d divisor\n",
            apic_ticks_per_ms, apic_divisor);
}

static void calibrate_tsc(void)
{
    ASSERT(arch_ints_disabled());
    ASSERT(ticks_per_ms <= 0xffff);

    uint64_t best_time = UINT64_MAX;
    for (int tries = 0; tries < 3; ++tries) {
        // Make the PIT run for 1ms
        uint16_t init_pic_count = ticks_per_ms;
        // Program PIT in the software strobe configuration, this makes
        // it just count down.  When it hits 0, it will wrap around and
        // keep counting, so we need to watch for overflow below.
        outp(I8253_CONTROL_REG, 0x38);
        outp(I8253_DATA_REG, init_pic_count & 0xff); // LSB
        outp(I8253_DATA_REG, init_pic_count >> 8); // MSB

        // Use CPUID to serialize the instruction stream
        uint32_t _ignored;
        cpuid(0, &_ignored, &_ignored, &_ignored, &_ignored);
        uint64_t start = rdtsc();
        uint16_t count = 0;
        do {
            // Latch the count for channel 0 (does not pause the actual
            // count)
            outp(I8253_CONTROL_REG, 0x00);
            count = inp(I8253_DATA_REG);
            count |= inp(I8253_DATA_REG) << 8;
        } while (count <= init_pic_count && count != 0);
        cpuid(0, &_ignored, &_ignored, &_ignored, &_ignored);
        uint64_t end = rdtsc();

        uint64_t tsc_ticks = end - start;
        if (tsc_ticks < best_time) {
            best_time = tsc_ticks;
        }
        LTRACEF("Calibration trial %d found %llu ticks/ms\n",
                tries, tsc_ticks);
    }

    tsc_ticks_per_ms = best_time;

    LTRACEF("TSC calibrated: %llu ticks/ms\n", tsc_ticks_per_ms);
}

void platform_init_timer(uint level)
{
    invariant_tsc = x86_feature_test(X86_FEATURE_INVAR_TSC);
    ticks_per_ms = INTERNAL_FREQ/1000;
    calibrate_apic_timer();
    if (invariant_tsc) {
        calibrate_tsc();
        // Program PIT in the software strobe configuration, but do not load
        // the count.  This will pause the PIT.
        outp(I8253_CONTROL_REG, 0x38);
    } else {
        timer_current_time = 0;
        set_pit_frequency(1000); // ~1ms granularity

        uint32_t irq = apic_io_isa_to_global(ISA_IRQ_PIT);
        register_int_handler(irq, &pit_timer_tick, NULL);
        unmask_interrupt(irq);
    }
}
LK_INIT_HOOK(timer, &platform_init_timer, LK_INIT_LEVEL_VM + 3);

status_t platform_set_oneshot_timer(platform_timer_callback callback,
                                    void *arg, lk_time_t interval)
{
    DEBUG_ASSERT(arch_ints_disabled());
    uint cpu = arch_curr_cpu_num();

    t_callback[cpu] = callback;
    callback_arg[cpu] = arg;

    if (interval > MAX_TIMER_INTERVAL)
        interval = MAX_TIMER_INTERVAL;
    if (interval < 1) interval = 1;

    uint8_t extra_divisor = 1;
    while (apic_ticks_per_ms > UINT32_MAX / interval / extra_divisor) {
        extra_divisor *= 2;
    }
    uint32_t count = (apic_ticks_per_ms / extra_divisor) * interval;
    uint32_t divisor = apic_divisor * extra_divisor;
    ASSERT(divisor <= UINT8_MAX);
    LTRACEF("Scheduling oneshot timer: %u count, %d div\n", count, divisor);
    return apic_timer_set_oneshot(count, divisor, false /* unmasked */);
}

void platform_stop_timer(void)
{
    /* Enable interrupt mode that will stop the decreasing counter of the PIT */
    //outp(I8253_CONTROL_REG, 0x30);
    apic_timer_stop();
}
