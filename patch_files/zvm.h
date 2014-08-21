/*
 * ZeroVM API. contains function prototypes, data structures,
 * macro definitions, types and constants
 *
 * Copyright (c) 2012, LiteStack, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef ZVM_API_H__
#define ZVM_API_H__ 1

#include <stdint.h>
#include <stddef.h> //size_t 
#include <unistd.h> //ssize_t 
#include <sys/syscall.h>   /* For SYS_xxx definitions */

/* zerovm system calls */
enum TrapCalls
{
  TrapRead = 0x64616552,
  TrapWrite = 0x74697257,
  TrapJail = 0x6c69614a,
  TrapUnjail = 0x6c6a6e55,
  TrapExit = 0x74697845,
  TrapFork = 0x6b726f46
};

/* channel types */
enum ChannelType {
  SGetSPut, /* sequential read, sequential write */
  RGetSPut, /* random read, sequential write */
  SGetRPut, /* sequential read, random write */
  RGetRPut /* random read, random write */
};

/* channel limits */
enum ChannelLimits {
  GetsLimit,
  GetSizeLimit,
  PutsLimit,
  PutSizeLimit,
  LimitsNumber
};

/* channel descriptor */
struct ZVMChannel
{
  int64_t limits[LimitsNumber];
  int64_t size; /* 0 for sequential channels */
  enum ChannelType type;
  char *name;
};

/* system data available for the user */
struct UserManifest
{
  void *heap_ptr;
  uint32_t heap_size;
  uint32_t stack_size;
  int32_t channels_count;
  struct ZVMChannel *channels;
};

extern ssize_t zvm_pread (int fd, void *buf, size_t nbytes, off_t offset);
extern ssize_t zvm_pwrite (int fd, const void *buf, size_t n, off_t offset);
extern void zvm_exit(int status);

#define MANIFEST ((const struct UserManifest const *)(extern_manifest))
extern struct UserManifest* extern_manifest;

extern void prepare_zrt_host();

#define zvm_jail(buffer, size) 0
#define zvm_unjail(buffer, size) 0

#define zvm_fork() 1

#endif /* ZVM_API_H__ */
