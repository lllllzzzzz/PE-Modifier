#include <windows.h>
#include <stdio.h>

#define NUM_GOOD_ARGS 2

int main(int argc, char *argv[])
{
    if (argc != NUM_GOOD_ARGS) {
        fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
        return -1;
    }

    HANDLE                  file;
    HANDLE                  fileMap;
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS       ntHeaders;
    PIMAGE_SECTION_HEADER   section;
    PIMAGE_SECTION_HEADER   sectionHeader;
    HMODULE                 user32;
    LPBYTE                  map;
    DWORD                   fileSize;

    file = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ |
        FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening %s!\n", argv[1]);
        return -1;
    }

    fileSize = GetFileSize(file, 0);
    if (!fileSize) {
        fprintf(stderr, "File size is 0 bytes!\n");
        CloseHandle(file);
        return -1;
    }

    fileMap = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if (!fileMap) {
        fprintf(stderr, "Error mapping file to memory!\n");
        CloseHandle(file);
        return -1;
    }

    map = MapViewOfFile(fileMap, FILE_MAP_ALL_ACCESS, 0, 0, fileSize);
    if (!fileMap) {
        fprintf(stderr, "Error creating map view of file!");
        CloseHandle(fileMap);
        CloseHandle(file);
        return -1;
    }

    dosHeader = (PIMAGE_DOS_HEADER)map;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "MZ header not found! This file is not a valid PE.");
        //free(dosHeader);
        CloseHandle(map);
        CloseHandle(fileMap);
        CloseHandle(file);
        return -1;
    }

    ntHeaders = (PIMAGE_NT_HEADERS) ((DWORD) map + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "NT signature not found! This file is not a valid PE.");
        free(ntHeaders);
        free(dosHeader);
        CloseHandle(map);
        CloseHandle(fileMap);
        CloseHandle(file);
        return -1;
    }

    free(ntHeaders);
    free(dosHeader);
    CloseHandle(map);
    CloseHandle(fileMap);
    CloseHandle(file);

    return 0;
}
