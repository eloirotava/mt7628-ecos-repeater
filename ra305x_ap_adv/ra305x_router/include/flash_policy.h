#ifndef TOMADA_FLASH_POLICY_H
#define TOMADA_FLASH_POLICY_H
/* BFROS EN25F16, 2 MiB: boot/env, config sector, calibration, uImage. */
#define TF_CFG_FIRST 0x31000U
#define TF_CFG_END 0x36000U
#define TF_CFG_SECTOR_FIRST 0x30000U
#define TF_CFG_SECTOR_END 0x40000U
#define TF_FW_FIRST 0x50000U
#define TF_FLASH_END 0x200000U
static int tf_span(unsigned int addr, unsigned int len,
                   unsigned int first, unsigned int end)
{
    return len != 0 && addr >= first && addr < end && len <= end - addr;
}
#endif
