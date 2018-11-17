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
 * The test application demonstrates the use of the APDS99XX driver and
 * polling the data every 200 ms.
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
#include "xtimer.h"

#include "apds99xx.h"
#include "apds99xx_params.h"

#define SLEEP   (200 * US_PER_MS)

int main(void)
{
    apds99xx_t dev;

    puts("APDS99XX proximity and ambient light sensor driver test application\n");
    puts("Initializing APDS99XX sensor");

    /* initialize the sensor with default configuration parameters */
    if (apds99xx_init(&dev, &apds99xx_params[0]) == APDS99XX_OK) {
        puts("[OK]\n");
    }
    else {
        puts("[Failed]");
        return 1;
    }

    while (1) {

        /* wait for 200 ms */
        xtimer_usleep(SLEEP);

        /* check whether ambient light and proximity data are available */
        if (apds99xx_data_ready_als(&dev) == APDS99XX_OK &&
            apds99xx_data_ready_prx(&dev) == APDS99XX_OK) {

            uint16_t als;
            uint16_t prx;

            if (apds99xx_read_prx_raw(&dev, &prx) == APDS99XX_OK) {
                printf("proximity = %d [cnts]\n", prx);
            }

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

            printf("+-------------------------------------+\n");
        }
    }
    return 0;
}
