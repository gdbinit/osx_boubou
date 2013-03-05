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
 * structures.h
 *
 */

#ifndef boubou_library_structures_h
#define boubou_library_structures_h

#include <stdint.h>

struct virus_payload_info
{
    char *virusName;             // virus library name
    uint8_t *virusAddress;       // address where virus library is located in memory
    uint8_t *payloadLocation;    // where inside the library is the encrypted payload
    uint64_t payloadSize;        // its size
    uint32_t infectedImageIndex; // the dyld index of the infected image
    uint8_t *infectedImage;      // ptr to the location of the infected image
    uint32_t infectedFileType;   // infected is library or main binary
};

typedef struct virus_payload_info virus_payload_info_t;

struct my_thread_command
{
    uint32_t cmd;
	uint32_t cmdsize;
	uint32_t flavor;
	uint32_t count;
};

typedef struct my_thread_command thread_command_t;

#endif
