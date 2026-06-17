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

void decrypt_file(const char *path){
    size_t len = strlen(path);
    if(len < 7 || _stricmp(path + len - 7, ".locked") != 0)
        return;

    ifstream in(path, ios::in | ios::binary | ios::ate);
    if(!in) return;

    size_t size = (size_t)in.tellg();
    in.seekg(0, ios::beg);
    if(size <= 0){ in.close(); return; }

    byte* cipher = new byte[size];
    in.read(reinterpret_cast<char*>(cipher), size);
    in.close();

    byte key[AES::DEFAULT_KEYLENGTH] = { '9','1','8','2','7','3','6','4','5' };
    byte iv[AES::BLOCKSIZE] = { '9','1','8','2','7','3','6','4','5' };

    byte* plain = new byte[size];
    CFB_Mode<AES>::Decryption dec(key, AES::DEFAULT_KEYLENGTH, iv);
    dec.ProcessData(plain, cipher, size);

    char out_name[MAX_PATH];
    memcpy(out_name, path, len - 7);
    out_name[len - 7] = '\0';

    ofstream out(out_name, ios::out | ios::binary | ios::trunc);
    if(out){
        out.write(reinterpret_cast<char*>(plain), size);
        out.close();
    }

    if(!DeleteFileA(path))
        cout << "  Could not delete: " << path << endl;

    delete[] cipher;
    delete[] plain;
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

        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", dir, findData.cFileName);

        if(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            walk(full);
        else
            decrypt_file(full);
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
        cout << "'stuff' folder not found. Run lock.exe first." << endl;
        return 0;
    }

    cout << "Unlocking: " << stuff << endl;
    walk(stuff);
    cout << "Done." << endl;
    return 0;
}
