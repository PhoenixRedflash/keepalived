/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        bfd_data.c include file.
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2015-2023 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _BFD_DATA_H
#define _BFD_DATA_H

#include <stdbool.h>
#include <stdio.h>

#include "bfd.h"
#include "sockaddr.h"

typedef struct _bfd_data {
	list_head_t	bfd;		/* bfd_t - BFD instances */
	int		fd_in;		/* Input socket fd */
	int		multihop_fd_in;	/* Input socket for multihop */
	thread_ref_t	thread_in;	/* Input socket thread */
} bfd_data_t;

#define BFD_BUFFER_SIZE 32

/* Global Vars exported */
extern bfd_data_t *bfd_data;
extern bfd_data_t *old_bfd_data;
extern char *bfd_buffer;

extern bfd_t *alloc_bfd(const char *);
extern void free_bfd(bfd_t *);
extern bfd_data_t *alloc_bfd_data(void);
extern void dump_bfd_data(FILE *, const bfd_data_t *);
#ifndef _ONE_PROCESS_DEBUG_
extern void dump_bfd_data_global(FILE *);
#endif
extern void bfd_print_data(void);
extern void free_bfd_data(bfd_data_t **);
extern void bfd_complete_init(void);
extern void alloc_bfd_buffer(void);
extern void free_bfd_buffer(void);
extern bfd_t *find_bfd_by_addr(const sockaddr_t *, const sockaddr_t *, bool) __attribute__ ((pure));
extern bfd_t *find_bfd_by_discr(const uint32_t) __attribute__ ((pure));
extern bfd_t *find_bfd_by_name(const char *) __attribute__ ((pure));
extern uint32_t rand_intv(uint32_t, uint32_t);
extern uint32_t bfd_get_random_discr(bfd_data_t *);

#endif				/* _BFD_DATA_H */
