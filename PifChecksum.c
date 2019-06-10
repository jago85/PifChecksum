/*
*   MIT License
*   
*   Copyright (c) 2019 jago85
*   
*   Permission is hereby granted, free of charge, to any person obtaining a copy
*   of this software and associated documentation files (the "Software"), to deal
*   in the Software without restriction, including without limitation the rights
*   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*   copies of the Software, and to permit persons to whom the Software is
*   furnished to do so, subject to the following conditions:
*   
*   The above copyright notice and this permission notice shall be included in all
*   copies or substantial portions of the Software.
*   
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*   SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAGIC_NUMBER (0x6c078965)

typedef uint32_t (*ReadCallback_t)(uint32_t offset, void *arg);

typedef struct CheckSumInfo {
    uint32_t Buffer[16];
    ReadCallback_t Read;
    void * ReadArg;
    uint32_t ChecksumLow;
    uint32_t ChecksumHigh;
} CheckSumInfo_t;

uint32_t ChecksumFunction(uint32_t a0, uint32_t a1, uint32_t a2);
void InitializeChecksum(CheckSumInfo_t *info, uint32_t seed, ReadCallback_t readCb, void * readArg);
void CalculateChecksum(CheckSumInfo_t *info);
void FinalizeChecksum(CheckSumInfo_t *info);

uint32_t ChecksumFunction(uint32_t a0, uint32_t a1, uint32_t a2)
{
    uint32_t res;
    uint64_t prod;
    uint32_t hi, lo;
    uint32_t diff;

    if (a1 == 0)
        a1 = a2;

    prod = (uint64_t)a0 * (uint64_t)a1;
    hi = (uint32_t)(prod >> 32);
    lo = (uint32_t)prod;
    diff = hi - lo;
    if (diff == 0)
        res = a0;
    else
        res = diff;
    return res;
}

void InitializeChecksum(CheckSumInfo_t *info, uint32_t seed, ReadCallback_t readCb, void * readArg)
{
    uint32_t init, data, loop;

    if (!info)
        return;
    if (!readCb)
        return;

    info->Read = readCb;
    info->ReadArg = readArg;

    // create the initialization data
    init = MAGIC_NUMBER * (seed & 0xff) + 1;
    data = info->Read(0, info->ReadArg);
    init ^= data;

    // copy to the buffer
    for (loop = 0; loop < 16; loop++)
    {
        info->Buffer[loop] = init;
    }
}

void CalculateChecksum(CheckSumInfo_t *info)
{
    uint32_t sum, loop;
    uint32_t data, dataNext, dataLast;
    uint32_t s2Tmp, s5Tmp, a3Tmp;
    uint32_t dataIndex;
    uint32_t shift;
    uint32_t dataShiftedRight, dataShiftedLeft;

    if (!info)
        return;

    dataIndex = 0;

    loop = 0;
    data = info->Read(0, info->ReadArg);
    do
    {
        loop++;
        dataLast = data;
        data = info->Read(dataIndex, info->ReadArg);
        dataIndex += 4;
        dataNext = info->Read(dataIndex, info->ReadArg);

        // 0xa400120c
        sum = ChecksumFunction(1007 - loop, data, loop);
        info->Buffer[0] += sum;

        // 0xa4001228
        sum = ChecksumFunction(info->Buffer[1], data, loop);
        info->Buffer[1] = sum;
        info->Buffer[2] ^= data;

        // 0xa400124c
        sum = ChecksumFunction(data + 5, MAGIC_NUMBER, loop);
        info->Buffer[3] += sum;

        // 0xa4001260
        if (dataLast < data)
        {
            // 0xa4001270
            sum = ChecksumFunction(info->Buffer[9], data, loop);
            info->Buffer[9] = sum;
        }
        else
        {
            info->Buffer[9] += data;
        }

        // 0xa400128c
        shift = dataLast & 0x1f;
        dataShiftedRight = data >> shift;
        dataShiftedLeft = data << (32 - shift);
        s5Tmp = dataShiftedRight | dataShiftedLeft; // reused later
        info->Buffer[4] += s5Tmp;

        dataShiftedLeft = data << shift;
        dataShiftedRight = data >> (32 - shift);

        // 0xa40012bc
        sum = ChecksumFunction(info->Buffer[7], dataShiftedLeft | dataShiftedRight, loop);
        info->Buffer[7] = sum;

        // 0xa40012d0
        if (data < info->Buffer[6])
        {
            info->Buffer[6] = (info->Buffer[3] + info->Buffer[6]) ^ (data + loop);
        }
        else
        {
            info->Buffer[6] = (info->Buffer[4] + data) ^ info->Buffer[6];
        }

        // 0xa4001300
        shift = dataLast >> 27;
        dataShiftedRight = data >> (32 - shift);
        dataShiftedLeft = data << shift;
        s2Tmp = dataShiftedLeft | dataShiftedRight; // reused later
        info->Buffer[5] += s2Tmp;

        dataShiftedLeft = data << (32 - shift);
        dataShiftedRight = data >> shift;

        // 0xa4001330
        sum = ChecksumFunction(info->Buffer[8], dataShiftedRight | dataShiftedLeft, loop);
        info->Buffer[8] = sum;

        // exit loop here
        // 0xa400133c
        if (loop == 1008)
            break;

        // 0xa400134c
        sum = ChecksumFunction(info->Buffer[15], s2Tmp, loop);

        // 0xa4001354
        shift = data >> 27;
        dataShiftedLeft = dataNext << shift;
        dataShiftedRight = dataNext >> (32 - shift);

        // 0xa400136c
        sum = ChecksumFunction(sum, dataShiftedLeft | dataShiftedRight, loop);
        info->Buffer[15] = sum;

        // 0xa4001380
        sum = ChecksumFunction(info->Buffer[14], s5Tmp, loop);

        // 0xa4001388
        shift = data & 0x1f;
        s2Tmp = shift; // reused later
        dataShiftedLeft = dataNext << (32 - shift);
        dataShiftedRight = dataNext >> shift;

        // 0xa40013a0
        sum = ChecksumFunction(sum, dataShiftedRight | dataShiftedLeft, loop);
        info->Buffer[14] = sum;

        // 0xa40013a8
        dataShiftedRight = data >> s2Tmp;
        dataShiftedLeft = data << (32 - s2Tmp);
        a3Tmp = dataShiftedRight | dataShiftedLeft;

        shift = dataNext & 0x1f;
        dataShiftedRight = dataNext >> shift;
        dataShiftedLeft = dataNext << (32 - shift);

        info->Buffer[13] += a3Tmp + (dataShiftedRight | dataShiftedLeft);

        // 0xa40013e8
        sum = ChecksumFunction(info->Buffer[10] + data, dataNext, loop);
        info->Buffer[10] = sum;

        // 0xa4001400
        sum = ChecksumFunction(info->Buffer[11] ^ data, dataNext, loop);
        info->Buffer[11] = sum;

        // 0xa4001408
        info->Buffer[12] += info->Buffer[8] ^ data;

    } while (1);
}

void FinalizeChecksum(CheckSumInfo_t *info)
{
    uint32_t buf[4];
    uint64_t checksum;
    uint32_t sum, loop;
    uint32_t data, tmp, s2Tmp;

    uint32_t shift;
    uint32_t dataShiftedRight, dataShiftedLeft;

    if (!info)
        return;

    data = info->Buffer[0];
    buf[0] = data;
    buf[1] = data;
    buf[2] = data;
    buf[3] = data;

    for (loop = 0; loop < 16; loop++)
    {
        data = info->Buffer[loop];

        // 0xa400144c
        shift = data & 0x1f;
        dataShiftedLeft = data << (32 - shift);
        dataShiftedRight = data >> shift;
        tmp = buf[0] + (dataShiftedRight | dataShiftedLeft);
        buf[0] = tmp;

        // 0xa400146c
        if (data < tmp)
        {
            // 0xa4001474
            buf[1] += data;
        }
        else
        {
            // 0xa400148c
            sum = ChecksumFunction(buf[1], data, loop);
            buf[1] = sum;
        }

        // 0xa4001498
        tmp = (data & 0x02) >> 1;
        s2Tmp = data & 0x01;

        // 0xa40014a4
        if (tmp == s2Tmp)
        {
            // 0xa40014ac
            buf[2] += data;
        }
        else
        {
            // 0xa40014c4
            sum = ChecksumFunction(buf[2], data, loop);
            buf[2] = sum;
        }

        // 0xa40014d0
        if (s2Tmp == 1)
        {
            buf[3] ^= data;
        }
        else
        {
            sum = ChecksumFunction(buf[3], data, loop);
            buf[3] = sum;
        }
    }

    // 0xa4001510
    sum = ChecksumFunction(buf[0], buf[1], 16);
    tmp = buf[3] ^ buf[2];

    checksum = (uint64_t)sum << 32;
    checksum |= tmp;
    checksum &= 0xffffffffffffull;

    info->ChecksumLow = (uint32_t)checksum;
    info->ChecksumHigh = (uint32_t)(checksum >> 32);
}

// --- End of checksum algorithm related stuff --------------------------------



// read a u32 from byte swapped buffer
uint32_t ReadWordByteSwapped(uint32_t offset, void *arg)
{
    uint8_t *src = (uint8_t *)arg;
    uint32_t res;

    if (src == NULL)
        return 0;

    res = src[offset + 1] << 24;
    res |= src[offset + 0] << 16;
    res |= src[offset + 3] << 8;
    res |= src[offset + 2] << 0;

    return res;
}

// read a u32 from big endian buffer
uint32_t ReadWordBigEndian(uint32_t offset, void *arg)
{
    uint8_t *src = (uint8_t *)arg;
    uint32_t res;

    if (src == NULL)
        return 0;

    res = src[offset + 0] << 24;
    res |= src[offset + 1] << 16;
    res |= src[offset + 2] << 8;
    res |= src[offset + 3] << 0;

    return res;
}

// read a u32 from little endian buffer
uint32_t ReadWordLittleEndian(uint32_t offset, void *arg)
{
    uint8_t *src = (uint8_t *)arg;
    uint32_t res;

    if (src == NULL)
        return 0;

    res = src[offset + 3] << 24;
    res |= src[offset + 2] << 16;
    res |= src[offset + 1] << 8;
    res |= src[offset + 0] << 0;

    return res;
}

void ChecksumFile(char *filename, uint32_t seed)
{
    ReadCallback_t callback;
    CheckSumInfo_t checksumInfo;
    uint8_t * bootcode;

    // open the file
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        printf("Could not open file %s\r\n", filename);
        return;
    }

    // allocate 4 kB buffer
    bootcode = (uint8_t *)malloc(0x1000);
    if (!bootcode)
    {
        printf("Out of memory\r\n");
        fclose(fp);
        return;
    }

    // read the first 4 kB of data
    if (0x1000 != fread(bootcode, 1, 0x1000, fp))
    {
        printf("Error reading file\r\n");
        fclose(fp);
        free(bootcode);
        return;
    }

    // determine byte order
    switch (*(uint32_t *)bootcode)
    {
    case 0x40123780:
        callback = ReadWordBigEndian;
        break;
    case 0x12408037:
        callback = ReadWordByteSwapped;
        break;
    case 0x80371240:
        callback = ReadWordLittleEndian;
        break;
    default:
        printf("Could not recognize byte swapping... using big endian read method\r\n");
        callback = ReadWordBigEndian;
    }

    // initialize the Checksum with the given seed
    // bootcode starts at offset 0x40
    InitializeChecksum(&checksumInfo, seed, callback, &bootcode[0x40]);

    // run the checksum algorithm
    CalculateChecksum(&checksumInfo);

    // finalize the checksum to get the result
    FinalizeChecksum(&checksumInfo);

    // present the result
    printf("Checksum: 0x%04X %08X\r\n", checksumInfo.ChecksumHigh, checksumInfo.ChecksumLow);

    // cleanup
    fclose(fp);
    fp = NULL;
    free(bootcode);
    bootcode = NULL;
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("usage: PifChecksum rom seed\r\n");
        printf("example: PifChecksum sm64.v64 3f3f\r\n");
        return -1;
    }

    uint32_t seed = strtol(argv[2], NULL, 16);
    char *filename = argv[1];
    ChecksumFile(filename, seed);
}
