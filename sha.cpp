#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <string>

std::string calcularSHA(const std::string& mensaje) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, mensaje.c_str(), mensaje.length());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

int main() {
    std::string mensaje = "Hola, este es un mensaje de ejemplo";
    std::string sha = calcularSHA(mensaje);
    std::cout << "Mensaje: " << mensaje << std::endl;
    std::cout << "SHA256: " << sha << std::endl;

    return 0;
}