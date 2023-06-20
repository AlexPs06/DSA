#include <stdlib.h>
#include <math.h>
#include <gmp.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include <openssl/sha.h>
#include <assert.h>
#include <string>
#include <iomanip>
using namespace std;



void keys_alice_bob(mpz_t clave_privada_alice, mpz_t clave_efimera_bob, 
                    mpz_t clave_publica_alice, mpz_t primo_p, mpz_t primo_q, mpz_t generador );
void inicialize_DSA(mpz_t p,mpz_t q, mpz_t g, int numBits );
void DSA_signature(mpz_t clave_privada_alice, mpz_t clave_efimera_bob, 
                    mpz_t msg, mpz_t r, mpz_t s,
                    mpz_t primo_p, mpz_t primo_q, mpz_t generador );
bool DSA_signature_verification(mpz_t clave_publica_alice, 
                    mpz_t msg, mpz_t r, mpz_t s,
                    mpz_t primo_p, mpz_t primo_q, mpz_t generador );
std::string calcularSHA1(const std::string& mensaje);

int main(){
    mpz_t generador, primo_p, primo_q;
    mpz_t clave_publica_alice;
    mpz_t clave_privada_alice;
    mpz_t clave_efimera_bob;

    mpz_t encrypted, decrypted;
    mpz_t sha_mpz;
    mpz_t r;
    mpz_t s;

    mpz_init(generador);
    mpz_init(primo_q);
    mpz_init(primo_p);
    mpz_init(sha_mpz);
    mpz_init(clave_privada_alice);
    mpz_init(clave_publica_alice);
    mpz_init(clave_efimera_bob);
    mpz_init(r);
    mpz_init(s);
    mpz_init(encrypted);
    mpz_init(decrypted);

    
    
    // mpz_init_set_str(generador, "2", 10); // Generador: 2
    // mpz_init_set_str(primo, "5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807", 10);   // Número primo: 353
    std::string sha = "Hola, este es un mensaje de ejemplo";
    sha = calcularSHA1(sha);

    mpz_set_str(sha_mpz, sha.c_str(),16);


    inicialize_DSA(primo_p, primo_q, generador, 2048 );


    printf("--------------------------Ejemplo---------------------------------------------------\n");

    printf("generador: %s\n", mpz_get_str(NULL, 0, generador));
    printf("primo p: %s\n", mpz_get_str(NULL, 0, primo_p));
    printf("primo q: %s\n", mpz_get_str(NULL, 0, primo_q));
    printf("------------------------------------------------------------------------------------\n");

    keys_alice_bob(clave_privada_alice, clave_efimera_bob, clave_publica_alice,  primo_p,  primo_q, generador );

    DSA_signature(clave_privada_alice, clave_efimera_bob, sha_mpz, r, s, primo_p, primo_q, generador );



    printf("clave_privada_alice: %s\n", mpz_get_str(NULL, 0, clave_privada_alice));
    printf("clave_publica_alice: %s\n", mpz_get_str(NULL, 0, clave_publica_alice));
    printf("clave_efimera_bob: %s\n", mpz_get_str(NULL, 0, clave_efimera_bob));
    printf("------------------------------------------------------------------------------------\n");

     printf("Firma r: %s\n", mpz_get_str(NULL, 0, r));
    printf("Firma S: %s\n", mpz_get_str(NULL, 0, s));
    printf("------------------------------------------------------------------------------------\n");
    bool verificated =  DSA_signature_verification(clave_publica_alice, sha_mpz,  r,  s,  primo_p,  primo_q,  generador );
    if(verificated){
        printf("Firma verificada si corresponde\n");
    }else{
        printf("Firma no verificada no corresponde\n");

    }

    printf("------------------------------------------------------------------------------------\n");

    // printf("clave_privada_alice: %s\n", mpz_get_str(NULL, 0, clave_privada_alice));
    // printf("clave_publica_alice: %s\n", mpz_get_str(NULL, 0, clave_publica_alice));
    // printf("clave_efimera_bob: %s\n", mpz_get_str(NULL, 0, clave_efimera_bob));
    // printf("------------------------------------------------------------------------------------\n");

    // printf("Mensaje: %s\n", mpz_get_str(NULL, 0, mensaje));
    // printf("Mensaje cifrado: %s\n", mpz_get_str(NULL, 0, encrypted));
    // printf("Mensaje descifrado: %s\n", mpz_get_str(NULL, 0, decrypted));
    // printf("------------------------------------------------------------------------------------\n");

    // printf("\n");

    mpz_clear(generador);
    mpz_clear(primo_p);
    mpz_clear(primo_q);
    mpz_clear(clave_publica_alice);
    mpz_clear(clave_privada_alice);
    mpz_clear(clave_efimera_bob);
    mpz_clear(sha_mpz);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(decrypted);
    mpz_clear(encrypted);
   
}

void inicialize_DSA(mpz_t p,mpz_t q, mpz_t g, int numBits ){
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    unsigned long seed = time(NULL);
    gmp_randseed_ui(randstate, seed);

    mpz_t e;
    mpz_t condicion;
    mpz_t h;
    mpz_init(e);
    mpz_init(condicion);
    mpz_init(h);
    int result=1; 

    while (result)
    {
        mpz_urandomb(p, randstate, numBits);  // Genera un número aleatorio con 'numBits' bits
        mpz_urandomb(q, randstate, 256);  // Genera un número aleatorio con 'numBits' bits
        //genero un primo de 2048
        mpz_nextprime (p, p);
        //genero un primo de 256
        mpz_nextprime (q, q);


        mpz_set_str(p, "89884656743115796742429711405763364460177151692783429800884652449310979263752253529349195459823881715145796498046459238345428121561386626945679753956400077352882071663925459750500807018254028771490434021315691357123734637046894876123496168716251735252662742462099334802433058472377674408598573487858308054417", 10);
        mpz_set_str(q, "1193447034984784682329306571139467195163334221569", 10);

        mpz_urandomm(h, randstate, p);

        // printf("p: %s\n", mpz_get_str(NULL, 0, p));

        // printf("q: %s\n", mpz_get_str(NULL, 0, q));

        // Asignar valores a 'temp' y 'condicion'
        mpz_set_str(e, "1", 10);
        mpz_set_str(condicion, "1", 10);

        // e=p-1
        mpz_sub(e, p, e);
        // printf("p-1: %s\n", mpz_get_str(NULL, 0, e));
        
        // e=e/q
        mpz_tdiv_qr(e,g,e,q);
        
        // printf("p-1/q: %s\n", mpz_get_str(NULL, 0, e));
        // printf("temp: %s\n", mpz_get_str(NULL, 0, temp));

        // g=h^e mod p
        mpz_powm(g, h, e, p);
        // printf("g=h^e mod p: %s\n", mpz_get_str(NULL, 0, g));


        // e = g^q mod p

        mpz_powm(e, g, q, p);


        // g^q mod p == 1
        int result = mpz_cmp(e, condicion);
        // printf("g^q mod p == 1: %s\n", mpz_get_str(NULL, 0, e));
        // printf("result: %i\n", result);
        if(result==0){
            break;
        }
        // exit(1);
    }

    //liberamos la memoria
    mpz_clear(condicion);
    mpz_clear(e);
    gmp_randclear(randstate);
}


void keys_alice_bob(mpz_t clave_privada_alice, mpz_t clave_efimera_bob, 
                    mpz_t clave_publica_alice, mpz_t primo_p, mpz_t primo_q, mpz_t generador ){
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    unsigned long seed = time(NULL);
    gmp_randseed_ui(randstate, seed);

    //Generar clave privada
    // a<-Z_p^*
    mpz_urandomm(clave_privada_alice, randstate, primo_q);
    // k<-Z_p^*
    mpz_urandomm(clave_efimera_bob, randstate, primo_q);

    // Generar claves públicas
    // A<-G^a mod P
    mpz_powm(clave_publica_alice, generador, clave_privada_alice, primo_p);

    gmp_randclear(randstate);
}



void DSA_signature(mpz_t clave_privada_alice, mpz_t clave_efimera_bob, 
                    mpz_t msg, mpz_t r, mpz_t s,
                    mpz_t primo_p, mpz_t primo_q, mpz_t generador ){

    mpz_t K_invert;
    mpz_init(K_invert);
    // r = g^k mod p
    mpz_powm(r, generador, clave_efimera_bob, primo_p);
    // r = r mod q
    mpz_mod(r,r,primo_q);

    //xr mod q
    mpz_mul(s, clave_privada_alice, r);
    mpz_mod(s,s,primo_q);

    // xr+z mod q
    mpz_add(s, msg, s);
    mpz_mod(s,s,primo_q);

    // k^-1 mod q
    mpz_invert(K_invert, clave_efimera_bob, primo_q);

    // k^-1 * (xr+z) mod q
    mpz_mul(s, K_invert, s);
    mpz_mod(s,s,primo_q);
}


bool DSA_signature_verification(mpz_t clave_publica_alice, 
                    mpz_t msg, mpz_t r, mpz_t s,
                    mpz_t primo_p, mpz_t primo_q, mpz_t generador ){

    mpz_t w;
    mpz_t u1;
    mpz_t u2;
    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);

    // s^-1 mod q
    mpz_invert(w, s, primo_q);

    //zw mod q
    mpz_mul(u1, msg, w);
    mpz_mod(u1,u1,primo_q);

    //rw mod q
    mpz_mul(u2, r, w);
    mpz_mod(u2,u2,primo_q);

    // u1 = g^u1 mod p
    mpz_powm(u1, generador, u1 , primo_p);
        
    // u2 = clave_publica_alice^u2 mod p
    mpz_powm(u2, clave_publica_alice, u2, primo_p);

    
    // u2 = u2*u1 mod p
    mpz_mul(u1, u1, u2);

    mpz_mod(u1,u1,primo_p);

    mpz_mod(u1,u1,primo_q);

    int resultado = mpz_cmp(u1, r);
    if (resultado == 0) {
        printf("Verificacion : %s\n", mpz_get_str(NULL, 0, u1));
        
        return true;
        // Las variables var1 y var2 son iguales
    } else {
        return false;
        // Las variables var1 y var2 son diferentes
    }

}



std::string calcularSHA256(const std::string& mensaje) {
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

std::string calcularSHA1(const std::string& mensaje) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, mensaje.c_str(), mensaje.length());
    SHA1_Final(hash, &sha1);

    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}