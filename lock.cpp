#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <climits>
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

namespace fs = std::filesystem;
using namespace CryptoPP;

const int SHRED_PASSES = 3;

fs::path get_base(){
#ifdef _WIN32
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    return fs::path(buf).parent_path();
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    _NSGetExecutablePath(buf, &size);
    return fs::path(buf).parent_path();
#else
    return fs::read_symlink("/proc/self/exe").parent_path();
#endif
}

void shred(const fs::path &path){
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if(ec || size == 0) return;

    std::fstream f(path.string(), std::ios::in | std::ios::out | std::ios::binary);
    if(!f) return;

    AutoSeededRandomPool rnd;
    std::vector<byte> buf(std::min((uintmax_t)65536, size));

    for(int pass = 0; pass < SHRED_PASSES; pass++){
        f.seekp(0, std::ios::beg);
        uintmax_t remaining = size;
        while(remaining > 0){
            size_t chunk = (size_t)std::min((uintmax_t)buf.size(), remaining);
            rnd.GenerateBlock(buf.data(), chunk);
            f.write(reinterpret_cast<char*>(buf.data()), chunk);
            remaining -= chunk;
        }
        f.flush();
    }

    f.close();
    fs::remove(path, ec);
}

bool has_locked_ext(const fs::path &p){
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == ".locked";
}

int main(){
    fs::path base = get_base();
    fs::path stuff = base / "stuff";
    fs::path keyfile = base / "key.bin";

    if(!fs::exists(stuff)){
        fs::create_directory(stuff);

        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        AutoSeededRandomPool rnd;
        rnd.GenerateBlock(key, sizeof(key));
        rnd.GenerateBlock(iv, sizeof(iv));

        std::ofstream kf(keyfile.string(), std::ios::out | std::ios::binary);
        kf.write(reinterpret_cast<char*>(key), sizeof(key));
        kf.write(reinterpret_cast<char*>(iv), sizeof(iv));
        kf.close();

        std::cout << "Created 'stuff' folder and generated key.bin" << std::endl;
        std::cout << "Place files in 'stuff' and run again." << std::endl;
        return 0;
    }

    std::ifstream kf(keyfile.string(), std::ios::in | std::ios::binary);
    if(!kf){
        std::cout << "key.bin not found. Delete 'stuff' folder and run again." << std::endl;
        return 1;
    }
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    kf.read(reinterpret_cast<char*>(key), sizeof(key));
    kf.read(reinterpret_cast<char*>(iv), sizeof(iv));
    kf.close();

    std::cout << "Locking: " << stuff << std::endl;

    std::error_code ec;
    for(auto &entry : fs::recursive_directory_iterator(stuff, ec)){
        if(!entry.is_regular_file()) continue;
        fs::path p = entry.path();
        if(has_locked_ext(p)) continue;

        std::ifstream in(p.string(), std::ios::in | std::ios::binary);
        if(!in) continue;
        std::vector<char> data((std::istreambuf_iterator<char>(in)), {});
        in.close();

        if(data.empty()) continue;

        std::vector<byte> plain(data.begin(), data.end());
        std::vector<byte> cipher(plain.size());

        CFB_Mode<AES>::Encryption enc(key, AES::DEFAULT_KEYLENGTH, iv);
        enc.ProcessData(cipher.data(), plain.data(), plain.size());

        std::ofstream out(p.string() + ".locked", std::ios::out | std::ios::binary);
        out.write(reinterpret_cast<char*>(cipher.data()), cipher.size());
        out.close();

        shred(p);
    }

    std::cout << "Done." << std::endl;
    return 0;
}
