/*
 * Copyright (C) 2018 Gunar Schorcht
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @brief       Test application for Vishay APDS99XX proximity and ambient light sensor
 * @author      Gunar Schorcht <gunar@schorcht.net>
 * @file
 *
 * The test application demonstrates the use of the APDS99XX driver with
 * interrupts.
 *
 * - Ambient light sensing (ALS) interrupt is used as data-ready interrupt
 *   which generates an interrupt in each cycle when the ALS has been finished.
 *
 * - Proximity sensing (PRX) interrupt is generated when the count value
 *   exceeds the threshold of 200. It doesn't use the low threshold.
 *
 * The application uses the following configurations:
 *
 * - 1 x ALS gain,
 * - 64 steps as ALS intergration time to use the full range of uint16_t,
 * - 8 IR LED pulses at 100 mA current for proximity sensing,
 * - 1 x proximity sensing gain, and,
 * - no waits.
 *
 * Depending on the sensor, a measurement cycle takes from 156 ms (APDS9950)
 * to 179 ms (APDS9960).
 */

#include <stdio.h>

#include "thread.h"
#include "thread_flags.h"
#include "xtimer.h"

#include "apds99xx.h"
#include "apds99xx_params.h"

/* thread flags are used to indicate interrupt events to a waiting thread */
#define APDS99XX_IRQ_FLAG  0x1000

/* reference to main thread */
thread_t* t_main;

static void apds99xx_isr (void *arg)
{
    /*
     * This ISR function is executed in the interrupt context. It must not be
     * blocking or time-consuming and must not access the sensor directly
     * via I2C.
     *
     * Therefore, the ISR function only indicates to the waiting thread that
     * an interrupt has occurred which needs to be handled in the thread
     * context.
     *
     * For this purpose, a message could be sent to the waiting thread.
     * However, sending a message in an ISR requires a message queue in
     * the waiting thread. Since it is not relevant how many interrupts
     * have occurred since last interrupt handling, but only that an
     * interrupt has occured, we simply use a thread flag here instead of
     * a message for simplicity.
     */
    (void)arg;
    thread_flags_set(t_main, APDS99XX_IRQ_FLAG);
}

int main(void)
{
    apds99xx_t dev;

    /* save the reference to the main thread */
    t_main = (thread_t*)sched_threads[sched_active_pid];

    /* initialize the sensor with default configuration parameters */
    puts("APDS99XX proximity and ambient light sensor driver test application\n");
    puts("Initializing APDS99XX sensor");

    if (apds99xx_init(&dev, &apds99xx_params[0]) == APDS99XX_OK) {
        puts("[OK]\n");
    }
    else {
        puts("[Failed]");
        return 1;
    }

    /* configure the interrupts */
    apds99xx_int_config_t int_cfg = {
        .als_int_en = true,     /* ALS interrupt enabled */
        .als_pers = 0,          /* ALS interrupt in each cylce (data-ready) */
        .prx_int_en = true,     /* PRX interrupt enabled */
        .prx_pers = 1,          /* PRX interrupt when 1 value is above threshold */
        .prx_thresh_low = 0,    /* PRX low threshold, cannot be exceeded */
        .prx_thresh_high = 200, /* PRX high threshold */
    };
    apds99xx_int_config(&dev, &int_cfg, apds99xx_isr, 0);

    while (1) {

        /* wait for an interrupt indicated by a thread flag */
        thread_flags_wait_one(APDS99XX_IRQ_FLAG);

        /* get the interrupt source (resets the interrupt line) */
        apds99xx_int_source_t int_src;
        apds99xx_int_source(&dev, &int_src);

        /* on proximity sensing interrupt */
        if (int_src.prx_int) {
            uint16_t prx;
            if (apds99xx_read_prx_raw(&dev, &prx) == APDS99XX_OK) {
                printf("proximity = %d [cnts]\n", prx);
            }

        }

        /* on ambient light sensing interrupt */
        if (int_src.als_int) {
            uint16_t als;
            if (apds99xx_read_als_raw(&dev, &als) == APDS99XX_OK) {
                printf("ambient = %d [cnts]\n", als);
            }

            #if MODULE_APDS9900 || MODULE_APDS9901 || MODULE_APDS9930
            if (apds99xx_read_illuminance(&dev, &als) == APDS99XX_OK) {
                printf("illuminance = %d [lux]\n", als);
            }
            #endif
            #if MODULE_APDS9950 || MODULE_APDS9960
            apds99xx_rgb_t rgb;

            if (apds99xx_read_rgb_raw(&dev, &rgb) == APDS99XX_OK) {
                printf("red = %d [cnts], green = %d [cnts], blue = %d [cnts]\n",
                       rgb.red, rgb.green, rgb.blue);
            }
            #endif
        }

        /* print final line only if there was at least one interrupt */
        if (int_src.prx_int || int_src.als_int) {
            printf("+-------------------------------------+\n");
        }
    }
    return 0;
}
