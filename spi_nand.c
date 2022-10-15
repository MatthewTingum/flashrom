/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2022
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Contains the generic SPI NAND framework
 */

#include <errno.h>
#include "chipdrivers.h"

// TODO: what doc specifies thse commands -- chip specific?
// it is a superset of the spi commands -- lets only include the new ones?
/* Commands */
#define SPINAND_READ_FROM_CACHE 0x03    /* TODO: Some datasheets also say 0x0b? */
#define SPINAND_GET_FEATURE 0x0f
#define SPINAND_SET_FEATURE 0x1f
#define SPINAND_READ_ID 0x90

/* Sub-Commands */
#define SPINAND_FEATURE_B0_IDR_E (0x01 << 6) // ID Read Enable
#define SPINAND_FEATURE_C0_OIP (0x01 << 0) // Operation In Progress

/* Registers */
#define CONFIG_REG_ADDR 0xb0    /* Some datasheets call this the OTP register */
#define STATUS_REG_ADDR 0xc0

/* */
#define SPINAND_ROW_ADDR_LEN 0x03
#define SPINAND_READ_PAGE 0x13
#define SPINAND_MAX_PARAMETER_PAGE_SIZE 512     /* TODO: Not true? */
#define SPINAND_COLUMN_ADDR_LEN 0x02
/* 1 dummy byte between input and output */
#define DUMMY_BYTE 1

#define CFG_PAGE_ROW    0x01
#define CFG_PAGE_COL    0x00

// Open NAND Flash Interface Specification
// TODO: Grab only the imporant parts that are consitant across revisions?
// TODO: size of page? ...
__attribute__((packed))
struct onfi_param_page {
	uint32_t page_signature;
	uint8_t revision_number;
	uint8_t features_supported;
	uint8_t optional_commands;
	uint8_t reserved_1[22];
	uint8_t device_mfr[12];
	uint8_t device_model[20];
	uint8_t mfr_id;
	uint16_t date_code;
	uint8_t reserved_2[13];
	uint32_t page_len;
	uint32_t spare_len;
	uint8_t reserved_3[6];
	// Number of pages per block
	uint32_t block_len;
	// Number of blocks per unit
	uint32_t unit_len;
	uint8_t num_units;
	uint8_t num_address_cycles;
	uint8_t bits_per_cell;
	// Number f maximum bad blocks per unit
	uint16_t max_bad_blocks;
	uint16_t block_endurance;
	uint8_t guarunteed_valid;
	uint16_t gtd_block_endurance;
	uint8_t partial_programs;
	uint8_t reserved_4;
	uint8_t ecc_bits;
	uint8_t interleaved_bits;
	uint8_t interleaved_op_attr;
	uint32_t reserved_5;
	uint16_t max_tprog;
	uint16_t max_bers;
	uint16_t max_tr;
	uint8_t reserved_6[25];
	uint16_t vendor_rev;
	uint16_t integrity_crc;
	uint8_t integrity_pad_1[256];
	uint8_t integrity_pad_2[256];
	// Additional redundant parameter pages
};

static uint8_t spi_nand_get_feature(struct flashctx *flash, unsigned char addr)
{
	// Feature will be outputted continuously until CS goes high
	int ret;
	const uint8_t cmd[] = { SPINAND_GET_FEATURE, addr };
	unsigned char cmd_resp[1];

	ret = spi_send_command(flash, sizeof(cmd), sizeof(cmd_resp), cmd, cmd_resp);
	if (ret) {
		msg_cerr("GET FEATURE failed!\n");
		// TODO: why? Does it get clobbered by the error print?
		errno = ret;
		return 0;
	}

	msg_cspew("GET FEATURE 0x%01x returned 0x%01x. ", addr, cmd_resp[1 - 1]);
	return cmd_resp[1 - 1];
}



// TODO: explain this
static int spi_nand_prepare_row_address(uint8_t cmd_buf[], const unsigned int addr)
{
	// TODO: a command buf length should be passed in
	cmd_buf[1] = (addr >> 16) & 0xff;
	cmd_buf[2] = (addr >>  8) & 0xff;
	cmd_buf[3] = (addr >>  0) & 0xff;
	// TODO: huh? -- inline instead
	return 3;
}

// TODO: see above
static int spi_nand_prepare_column_address(uint8_t cmd_buf[], const unsigned int addr)
{
	cmd_buf[1] = (addr >>  8) & 0xff;
	cmd_buf[2] = (addr >>  0) & 0xff;
	return 2;
}

static int spi_nand_wait(struct flashctx *flash)
{
	uint8_t feature_status;

	do {
		feature_status = spi_nand_get_feature(flash, STATUS_REG_ADDR);
		// TODO: time?
		//feature_status = spi_nand_get_feature_multi(flash, STATUS_REG_ADDR, 4);
		if (errno)
			return errno;
	} while (feature_status & SPINAND_FEATURE_C0_OIP);

	return 0;
}

static int spi_nand_set_feature(struct flashctx *flash, unsigned char addr, uint8_t feature)
{
	// Warning: feature will be kept after soft reset!
	const uint8_t cmd[] = { SPINAND_SET_FEATURE, addr, feature };

	return spi_send_command(flash, sizeof(cmd), 0, cmd, NULL);
}

static int spi_nand_read_page(struct flashctx *flash, unsigned int row_addr)
{
	uint8_t cmd[1 + SPINAND_ROW_ADDR_LEN] = { SPINAND_READ_PAGE, };

	int addr_len = spi_nand_prepare_row_address(cmd, row_addr);

	return spi_send_command(flash, 1 + addr_len, 0, cmd, NULL);
}

// TODO: consolidate and fix names
static int spi_nand_read_page_to_cache(struct flashctx *flash, unsigned int row_addr)
{
	int ret;

	ret = spi_nand_read_page(flash, row_addr);
	if (ret)
		return ret;
	return spi_nand_wait(flash);
}

static int spi_nand_read_cache(struct flashctx *flash, unsigned int column_addr,
		uint8_t *bytes, unsigned int len)
{
	uint8_t cmd[1 + SPINAND_COLUMN_ADDR_LEN] = { SPINAND_READ_FROM_CACHE, };

	int addr_len = spi_nand_prepare_column_address(cmd, column_addr);

	/* Send Read */
	// TODO: DUMMY_BYTE?
	return spi_send_command(flash, 1 + addr_len + DUMMY_BYTE, len, cmd, bytes);
}

// Read a page to the cache then read the cache
static int spi_nand_read_page_offset(struct flashctx *flash, unsigned int row_addr,
		unsigned int column_addr, uint8_t *bytes, unsigned int len,
		unsigned int chunksize)
{
	// Read data within one page
	int ret;

	// A page is read to the cache, then ECC is calculated and compared
	// Issue the read to cache and wait for it to complete
	if (chunksize == 0)
		chunksize = len;
	ret = spi_nand_read_page_to_cache(flash, row_addr);
	if (ret)
		return ret;

	while (len) {
		unsigned int data_to_read = min(chunksize, len);
		ret = spi_nand_read_cache(flash, column_addr, bytes, data_to_read);
		if (ret)
			return ret;
		len -= data_to_read;
		column_addr += data_to_read;
		bytes += data_to_read;
		printf("page %d\n",len);
	}

	return 0;
}

static int probe_ofni(struct flashctx *flash) {
	// Read the Parameter Page
	struct onfi_param_page parameters;
	uint8_t cfg_feature;
	int ret;

	// TODO: This is sometimes called the OTP reg addr
	// Get the config / OTP feature
	cfg_feature = spi_nand_get_feature(flash, CONFIG_REG_ADDR);
	if (errno) {
		msg_cerr("OFNI probe: get config feature failed\n");
		return -1;
	}

	// Set the OTP enable bit to 1 so the config page can be read
	// ONFI states that the parameter page can be read with command 0xec
	// This is more portable?
	// You would think that if READ_ID reports back OFNI then it would support OFNI commands
	// But judging by datasheets, some may return version 0x00?
	ret = spi_nand_set_feature(flash, CONFIG_REG_ADDR,
			cfg_feature | SPINAND_FEATURE_B0_IDR_E);
	if (ret) {
		msg_cerr("OFNI probe: OTP enable failed\n");
		return ret;
	}

	// Read the config page
	ret = spi_nand_read_page_offset(flash, CFG_PAGE_ROW, CFG_PAGE_COL,
			(uint8_t*)&parameters, SPINAND_MAX_PARAMETER_PAGE_SIZE, 0);
	if (ret) {
		msg_cerr("OFNI probe: read parameter page failed\n");
		return ret;
	}

	// Reset the config feature
	ret = spi_nand_set_feature(flash, CONFIG_REG_ADDR, cfg_feature);
	if (ret) {
		msg_cerr("OFNI probe: reset config feature failed\n");
		return ret;
	}

	msg_cdbg("SPI NAND probe returned");
	uint32_t i;
	for (i = 0; i < sizeof(parameters); i++)
		msg_cdbg(" %02x", ((uint8_t*)(&parameters))[i]);
	msg_cdbg("\n");

	return 0;
}

int probe_spi_nand(struct flashctx *flash)
{
	// TODO: perform a read id command to verify that this chip supports the ONFI spec
	// if (is_ofni)
		return probe_ofni(flash);

	return -1;
}
