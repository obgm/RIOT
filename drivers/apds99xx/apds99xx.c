/*
 * Copyright (C) 2018 Gunar Schorcht
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_apds99xx
 * @brief       Device driver for the Broadcom APDS99XX proximity and ambient light sensor
 * @author      Gunar Schorcht <gunar@schorcht.net>
 * @file
 * @{
 */

#include <string.h>
#include <stdlib.h>

#include "apds99xx_regs.h"
#include "apds99xx.h"

#include "irq.h"
#include "log.h"
#include "xtimer.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG

#define ASSERT_PARAM(cond) \
    if (!(cond)) { \
        DEBUG("[apds99xx] %s: %s\n", \
              __func__, "parameter condition (" # cond ") not fulfilled"); \
        assert(cond); \
    }

#define DEBUG_DEV(f, d, ...) \
        DEBUG("[apds99xx] %s i2c dev=%d addr=%02x: " f "\n", \
              __func__, d->params.dev, APDS99XX_I2C_ADDRESS, ## __VA_ARGS__);

#else /* ENABLE_DEBUG */

#define ASSERT_PARAM(cond) assert(cond);
#define DEBUG_DEV(f, d, ...)

#endif /* ENABLE_DEBUG */

#define ERROR_DEV(f, d, ...) \
        LOG_ERROR("[apds99xx] %s i2c dev=%d addr=%02x: " f "\n", \
                  __func__, d->params.dev, APDS99XX_I2C_ADDRESS, ## __VA_ARGS__);

#define EXEC_RET(f) { \
    int _r; \
    if ((_r = f) != APDS99XX_OK) { \
        DEBUG("[apds99xx] %s: error code %d\n", __func__, _r); \
        return _r; \
    } \
}

#define EXEC_RET_CODE(f, c) { \
    int _r; \
    if ((_r = f) != APDS99XX_OK) { \
        DEBUG("[apds99xx] %s: error code %d\n", __func__, _r); \
        return c; \
    } \
}

#define EXEC(f) { \
    int _r; \
    if ((_r = f) != APDS99XX_OK) { \
        DEBUG("[apds99xx] %s: error code %d\n", __func__, _r); \
        return; \
    } \
}

/** Forward declaration of functions for internal use */

static int _is_available(const apds99xx_t *dev);
static void _set_reg_bit(uint8_t *byte, uint8_t mask, uint8_t bit);
static int _reg_read(const apds99xx_t *dev, uint8_t reg, uint8_t *data, uint16_t len);
static int _reg_write(const apds99xx_t *dev, uint8_t reg, uint8_t *data, uint16_t len);
static int _update_reg(const apds99xx_t *dev, uint8_t reg, uint8_t mask, uint8_t val);

int apds99xx_init(apds99xx_t *dev, const apds99xx_params_t *params)
{
    /* some parameter sanity checks */
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(params != NULL);
    ASSERT_PARAM(params->als_steps <= 256);
    ASSERT_PARAM(params->wait_steps <= 256);
    #if MODULE_APDS9960
    ASSERT_PARAM(params->prx_pulses <= 15);
    #endif

    DEBUG_DEV("params=%p", dev, params);

    /* init sensor data structure */
    dev->params = *params;

    #if MODULE_APDS99XX_FULL
    dev->isr = NULL;
    dev->isr_arg = NULL;
    dev->gpio_init = false;
    #endif

    /* wait for 6 ms after power on reset */
    xtimer_usleep(6 * US_PER_MS);

    /* check availability of the sensor */
    EXEC_RET(_is_available(dev));

    uint8_t reg;

    /* disable and power down the sensor */
    reg = 0;
    EXEC_RET(_reg_write(dev, APDS99XX_REG_ENABLE, &reg, 1));

    /* write ALS integration time and gain parameter */
    uint8_t atime = 256 - dev->params.als_steps;
    EXEC_RET(_reg_write(dev, APDS99XX_REG_ATIME, &atime, 1));
    EXEC_RET(_update_reg(dev, APDS99XX_REG_CONTROL,
                              APDS99XX_REG_AGAIN, dev->params.als_gain));

    /* write PRX LED pulses LED drive strengh and gain parameter */
    #if MODULE_APDS9900 || MODULE_APDS9901 || MODULE_APDS9930
    uint8_t ptime = 0xff; /* PTIME is always 0xff as recommended in datasheet */
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PTIME, &ptime, 1));
    #endif
    #if MODULE_APDS9960
    if (dev->params.prx_pulses > 0) {
        EXEC_RET(_update_reg(dev, APDS99XX_REG_PPCOUNT,
                                  APDS99XX_REG_PPULSE, dev->params.prx_pulses-1));
    }
    #else
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PPCOUNT, &dev->params.prx_pulses, 1));
    EXEC_RET(_update_reg(dev, APDS99XX_REG_CONTROL, APDS99XX_REG_PDIODE, 2));
    #endif
    EXEC_RET(_update_reg(dev, APDS99XX_REG_CONTROL,
                              APDS99XX_REG_PDRIVE, dev->params.prx_drive));
    EXEC_RET(_update_reg(dev, APDS99XX_REG_CONTROL,
                              APDS99XX_REG_PGAIN, dev->params.prx_gain));

    /* write wating time */
    uint8_t wtime = 256 - dev->params.wait_steps;
    EXEC_RET(_reg_write(dev, APDS99XX_REG_WTIME, &wtime, 1));

    reg = 0;
    _set_reg_bit(&reg, APDS99XX_REG_PON, 1);                           /* power on */
    _set_reg_bit(&reg, APDS99XX_REG_AEN, dev->params.als_steps != 0);  /* enable ALS */
    _set_reg_bit(&reg, APDS99XX_REG_PEN, dev->params.prx_pulses != 0); /* enable PRX */
    _set_reg_bit(&reg, APDS99XX_REG_WEN, dev->params.wait_steps != 0); /* enable Wait */
    EXEC_RET(_reg_write(dev, APDS99XX_REG_ENABLE, &reg, 1));

    return APDS99XX_OK;
}

int apds99xx_data_ready_als (const apds99xx_t *dev)
{
    ASSERT_PARAM(dev != NULL);
    DEBUG_DEV("", dev);

    uint8_t reg;
    EXEC_RET(_reg_read(dev, APDS99XX_REG_STATUS, &reg, 1));

    return (reg & APDS99XX_REG_AVALID) ? APDS99XX_OK : -APDS99XX_ERROR_NO_DATA;
}

int apds99xx_read_als_raw(const apds99xx_t *dev, uint16_t *raw)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(raw != NULL);
    DEBUG_DEV("raw=%p", dev, raw);

    uint8_t data[6];

    EXEC_RET_CODE(_reg_read(dev, APDS99XX_REG_CDATAL, data, 2),
                  -APDS99XX_ERROR_RAW_DATA);

    /* data LSB @ lower address */
    *raw = (data[1] << 8) | data[0];

    return APDS99XX_OK;
}

#if MODULE_APDS9900 || MODULE_APDS9901 || MODULE_APDS9930
#include <math.h>
static uint8_t apds99xx_gains[] = { 1, 8, 16, 120 };

int apds99xx_read_illuminance(const apds99xx_t *dev, uint16_t *lux)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(lux != NULL);
    DEBUG_DEV("lux=%p", dev, lux);

    uint8_t data[4];
    EXEC_RET_CODE(_reg_read(dev, APDS99XX_REG_CDATAL, data, 4),
                  -APDS99XX_ERROR_RAW_DATA);

    /* data LSB @ lower address */
    uint16_t ch0 = (data[1] << 8) | data[0];
    uint16_t ch1 = (data[3] << 8) | data[2];

    /* define some device dependent constants */
    double df = 52;
    #if MODULE_APDS9900 || MODULE_APDS9901
    double ga = 0.48;   /* glas or lens attenuation factor */
    double b = 2.23;
    double c = 0.7;
    double d = 1.42;
    #else
    /* APDS_9930 */
    double ga = 0.49;   /* glas or lens attenuation factor */
    double b = 1.862;
    double c = 0.746;
    double d = 1.291;
    #endif

    /* algorithm from datasheet */
    double iac1 = ch0 - b * ch1;
    double iac2 = c * ch0 - d * ch1;

    /* iac = max(iac1, iac2, 0); */
    double iac = 0;
    iac = (iac1 > iac) ? iac1 : iac;
    iac = (iac2 > iac) ? iac2 : iac;

    double lpc = ga * df / (apds99xx_gains[dev->params.als_gain] *
                             dev->params.als_steps);
    double luxd = iac * lpc;
    *lux = luxd;

    return APDS99XX_OK;
}
#endif /* MODULE_APDS9900 || MODULE_APDS9901 || MODULE_APDS9930 */

#if MODULE_APDS9950 || MODULE_APDS9960
int apds99xx_read_rgb_raw(const apds99xx_t *dev, apds99xx_rgb_t *rgb)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(rgb != NULL);
    DEBUG_DEV("rgb=%p", dev, rgb);

    uint8_t data[6] = { }; /* initialize with 0 */

    EXEC_RET_CODE(_reg_read(dev, APDS99XX_REG_RDATAL, data, 6),
                  -APDS99XX_ERROR_RAW_DATA);

    /* data LSB @ lower address */
    rgb->val[0] = (data[1] << 8) | data[0];
    rgb->val[1] = (data[3] << 8) | data[2];
    rgb->val[2] = (data[5] << 8) | data[4];

    return APDS99XX_OK;
}
#endif /* MODULE_APDS9950 || MODULE_APDS9960 */

int apds99xx_data_ready_prx (const apds99xx_t *dev)
{
    ASSERT_PARAM(dev != NULL);
    DEBUG_DEV("", dev);

    uint8_t reg;
    EXEC_RET(_reg_read(dev, APDS99XX_REG_STATUS, &reg, 1));

    return (reg & APDS99XX_REG_PVALID) ? APDS99XX_OK : -APDS99XX_ERROR_NO_DATA;
}

int apds99xx_read_prx_raw (const apds99xx_t *dev, uint16_t *prox)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(prox != NULL);
    DEBUG_DEV("prox=%p", dev, prox);

    uint8_t data[2] = { }; /* initialize with 0 */

    #if MODULE_APDS9900 || MODULE_APDS9901 || MODULE_APDS9930 || MODULE_APDS9950
    EXEC_RET_CODE(_reg_read(dev, APDS99XX_REG_PDATAL, data, 2),
                  -APDS99XX_ERROR_RAW_DATA);
    #endif
    #if MODULE_APDS9960
    EXEC_RET_CODE(_reg_read(dev, APDS99XX_REG_PDATA, data, 1),
                  -APDS99XX_ERROR_RAW_DATA);
    #endif

    /* data LSB @ lower address */
    *prox = (data[1] << 8) | data[0];

     return APDS99XX_OK;
}

int apds99xx_power_down(apds99xx_t *dev)
{
    return _update_reg(dev, APDS99XX_REG_ENABLE, APDS99XX_REG_PON, 0);
}

int apds99xx_power_up(apds99xx_t *dev)
{
    return _update_reg(dev, APDS99XX_REG_ENABLE, APDS99XX_REG_PON, 1);
}

#if MODULE_APDS99XX_FULL

void _apds99xx_isr(void *arg)
{
    apds99xx_t* dev =  (apds99xx_t*)arg;
    unsigned state = irq_disable();

    DEBUG_DEV("", dev);

    /* call registered interrupt service routine */
    if (dev->isr) {
        dev->isr(dev->isr_arg);
    }

    irq_restore (state);
}

int apds99xx_int_source(apds99xx_t *dev, apds99xx_int_source_t* source)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(source != NULL);
    DEBUG_DEV("", dev);

    uint8_t reg;

    /* get interrupt status */
    EXEC_RET(_reg_read(dev, APDS99XX_REG_STATUS, &reg, 1));

    /* set triggered interrupts */
    source->als_int = reg & APDS99XX_REG_AINT;
    source->prx_int = reg & APDS99XX_REG_PINT;

    /* clear interrupt status */
    EXEC_RET(_reg_write(dev, APDS99XX_REG_CLI_CMD, 0, 0));

    return APDS99XX_OK;
}

int apds99xx_int_config(apds99xx_t *dev, apds99xx_int_config_t* cfg,
                        apds99xx_isr_t isr, void *isr_arg)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(cfg != NULL);
    ASSERT_PARAM(dev->params.int_pin != GPIO_UNDEF);
    ASSERT_PARAM(cfg->als_pers <= 15);
    ASSERT_PARAM(cfg->prx_pers <= 15);

    DEBUG_DEV("", dev);

    if (!dev->gpio_init) {
        dev->gpio_init = true;
        gpio_init_int(dev->params.int_pin, GPIO_IN_PU, GPIO_FALLING,
                      _apds99xx_isr, dev);
    }

    /* LSB @ lower address */
    uint8_t ailtx[2] = { cfg->als_thresh_low & 0xff, cfg->als_thresh_low >> 8 };
    uint8_t aihtx[2] = { cfg->als_thresh_high & 0xff, cfg->als_thresh_high >> 8 };
    #if MODULE_APDS9960
    /* for APDS9960 the one byte thresholds is used for APDS99XX_REG_PIxTH */
    uint8_t pilth = cfg->prx_thresh_low & 0xff;
    uint8_t pihth = cfg->prx_thresh_high & 0xff;
    #else
    uint8_t piltx[2] = { cfg->prx_thresh_low & 0xff, cfg->prx_thresh_low >> 8 };
    uint8_t pihtx[2] = { cfg->prx_thresh_high & 0xff, cfg->prx_thresh_high >> 8 };
    #endif

    EXEC_RET(_reg_write(dev, APDS99XX_REG_AILTL, ailtx, 2));
    EXEC_RET(_reg_write(dev, APDS99XX_REG_AIHTL, aihtx, 2));

    #if MODULE_APDS9960
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PILTH, &pilth, 1));
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PIHTH, &pihth, 1));
    #else
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PILTL, piltx, 2));
    EXEC_RET(_reg_write(dev, APDS99XX_REG_PIHTL, pihtx, 2));
    #endif
    EXEC_RET(_update_reg(dev, APDS99XX_REG_PERS, APDS99XX_REG_APERS, cfg->als_pers));
    EXEC_RET(_update_reg(dev, APDS99XX_REG_PERS, APDS99XX_REG_PPERS, cfg->prx_pers));

    EXEC_RET(_update_reg(dev, APDS99XX_REG_ENABLE, APDS99XX_REG_AIEN, cfg->als_int_en));
    EXEC_RET(_reg_write(dev, APDS99XX_REG_CLI_CMD, 0, 0));

    EXEC_RET(_update_reg(dev, APDS99XX_REG_ENABLE, APDS99XX_REG_PIEN, cfg->prx_int_en));
    EXEC_RET(_reg_write(dev, APDS99XX_REG_CLI_CMD, 0, 0));

    dev->isr = isr;
    dev->isr_arg = isr_arg;

    return APDS99XX_OK;
}

#endif /* MODULE_APDS99XX_FULL */

/** Functions for internal use only */

/**
 * @brief   Check the chip ID to test whether sensor is available
 */
static int _is_available(const apds99xx_t *dev)
{
    DEBUG_DEV("", dev);

    uint8_t reg;

    /* read the chip id from APDS99XX_REG_ID_X */
    EXEC_RET(_reg_read(dev, APDS99XX_REG_ID, &reg,1));

    if (reg != APDS99XX_ID) {
        DEBUG_DEV("sensor is not available, wrong device id %02x, "
                  "should be %02x", dev, reg, APDS99XX_ID);
        return -APDS99XX_ERROR_WRONG_ID;
    }

    return APDS99XX_OK;
}

static void _set_reg_bit(uint8_t *byte, uint8_t mask, uint8_t bit)
{
    ASSERT_PARAM(byte != NULL);

    uint8_t shift = 0;
    while (!((mask >> shift) & 0x01)) {
        shift++;
    }
    *byte = ((*byte & ~mask) | ((bit << shift) & mask));
}

static int _update_reg(const apds99xx_t *dev, uint8_t reg, uint8_t mask, uint8_t val)
{
    DEBUG_DEV("reg=%02x mask=%02x val=%02x", dev, reg, mask, val);

    uint8_t reg_val;
    uint8_t shift = 0;

    while (!((mask >> shift) & 0x01)) {
        shift++;
    }

    /* read current register value */
    EXEC_RET(_reg_read(dev, reg, &reg_val, 1));

    /* set masked bits to the given value  */
    reg_val = (reg_val & ~mask) | ((val << shift) & mask);

    /* write back new register value */
    EXEC_RET(_reg_write(dev, reg, &reg_val, 1));

    return APDS99XX_OK;
}

static int _reg_read(const apds99xx_t *dev, uint8_t reg, uint8_t *data, uint16_t len)
{
    ASSERT_PARAM(dev != NULL);
    ASSERT_PARAM(data != NULL);
    ASSERT_PARAM(len != 0);

    if (i2c_acquire(dev->params.dev)) {
        DEBUG_DEV("could not aquire I2C bus", dev);
        return -APDS99XX_ERROR_I2C;
    }
    int res = i2c_read_regs(dev->params.dev, APDS99XX_I2C_ADDRESS, reg, data, len, 0);
    i2c_release(dev->params.dev);

    if (res != APDS99XX_OK) {
        DEBUG_DEV("could not read %d bytes from sensor registers "
                  "starting at addr %02x, reason %d (%s)",
                  dev, len, reg, res, strerror(res * -1));
        return -APDS99XX_ERROR_I2C;
    }

    if (ENABLE_DEBUG) {
        printf("[apds99xx] %s i2c dev=%d addr=%02x: read from reg 0x%02x: ",
               __func__, dev->params.dev, APDS99XX_I2C_ADDRESS, reg);
        for (int i = 0; i < len; i++) {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }

    return res;
}

static int _reg_write(const apds99xx_t *dev, uint8_t reg, uint8_t *data, uint16_t len)
{
    ASSERT_PARAM(dev != NULL);

    if (ENABLE_DEBUG) {
        printf("[apds99xx] %s i2c dev=%d addr=%02x: write to reg 0x%02x: ",
               __func__, dev->params.dev, APDS99XX_I2C_ADDRESS, reg);
        for (int i = 0; i < len; i++) {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }

    if (i2c_acquire(dev->params.dev)) {
        DEBUG_DEV("could not aquire I2C bus", dev);
        return -APDS99XX_ERROR_I2C;
    }

    int res;

    if (!data || !len) {
        res = i2c_write_byte(dev->params.dev, APDS99XX_I2C_ADDRESS, reg, 0);
    }
    else {
        res = i2c_write_regs(dev->params.dev, APDS99XX_I2C_ADDRESS, reg, data, len, 0);
    }
    i2c_release(dev->params.dev);

    if (res != APDS99XX_OK) {
        DEBUG_DEV("could not write %d bytes to sensor registers "
                  "starting at addr 0x%02x, reason %d (%s)",
                  dev, len, reg, res, strerror(res * -1));
        return -APDS99XX_ERROR_I2C;
    }

    return res;
}
