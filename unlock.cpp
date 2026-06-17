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

int main(){
    fs::path base = get_base();
    fs::path stuff = base / "stuff";
    fs::path keyfile = base / "key.bin";

    if(!fs::exists(stuff)){
        std::cout << "'stuff' folder not found. Run lock.exe first." << std::endl;
        return 0;
    }

    if(!fs::exists(keyfile)){
        std::cout << "key.bin not found!" << std::endl;
        return 1;
    }

    std::ifstream kf(keyfile.string(), std::ios::in | std::ios::binary);
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    kf.read(reinterpret_cast<char*>(key), sizeof(key));
    kf.read(reinterpret_cast<char*>(iv), sizeof(iv));
    kf.close();

    std::cout << "Unlocking: " << stuff << std::endl;

    std::error_code ec;
    for(auto &entry : fs::recursive_directory_iterator(stuff, ec)){
        if(!entry.is_regular_file()) continue;
        fs::path p = entry.path();
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if(ext != ".locked") continue;

        std::ifstream in(p.string(), std::ios::in | std::ios::binary);
        if(!in) continue;
        std::vector<char> data((std::istreambuf_iterator<char>(in)), {});
        in.close();

        if(data.empty()) continue;

        std::vector<byte> cipher(data.begin(), data.end());
        std::vector<byte> plain(cipher.size());

        CFB_Mode<AES>::Decryption dec(key, AES::DEFAULT_KEYLENGTH, iv);
        dec.ProcessData(plain.data(), cipher.data(), cipher.size());

        fs::path out_path = p;
        out_path.replace_extension("");

        std::ofstream out(out_path.string(), std::ios::out | std::ios::binary);
        out.write(reinterpret_cast<char*>(plain.data()), plain.size());
        out.close();

        shred(p);
    }

    std::cout << "Done." << std::endl;
    return 0;
}
