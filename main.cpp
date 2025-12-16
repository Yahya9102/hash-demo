

#include <iostream>                                  
#include <string>                                     
#include <vector>                         
#include <iomanip>                                    
#include <sstream>                                   

#include <openssl/evp.h>                          
#include <argon2.h>                            

static std::string toHex(const unsigned char* data, unsigned int len) {  
    std::ostringstream oss;                          
    oss << std::hex << std::setfill('0');            

    for (unsigned int i = 0; i < len; i++) {      
        oss << std::setw(2) << static_cast<int>(data[i]); 
    }

    return oss.str();                                
}

static std::string hashWithEVP(const std::string& input, const EVP_MD* algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();            
    if (!ctx) {                                    
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    unsigned char out[EVP_MAX_MD_SIZE];              
    unsigned int outLen = 0;                         

    if (EVP_DigestInit_ex(ctx, algo, nullptr) != 1) { 
        EVP_MD_CTX_free(ctx);                       
        throw std::runtime_error("EVP_DigestInit_ex failed"); 
    }

    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) { 
        EVP_MD_CTX_free(ctx);                        
        throw std::runtime_error("EVP_DigestUpdate failed"); 
    }

    if (EVP_DigestFinal_ex(ctx, out, &outLen) != 1) {
        EVP_MD_CTX_free(ctx);              
        throw std::runtime_error("EVP_DigestFinal_ex failed"); 
    }

    EVP_MD_CTX_free(ctx);                        

    return toHex(out, outLen);                
}


static std::string argon2idHash(const std::string& password) {
    const uint32_t t_cost = 2;                   
    const uint32_t m_cost = 1 << 16;                  
    const uint32_t parallelism = 1;                  
    const uint32_t hashLen = 32;                      


    std::vector<unsigned char> salt = { 
        'd','e','m','o','-','s','a','l','t','-','1','2','3','4','5','6'
    };


    const size_t encodedLen = argon2_encodedlen(     
        t_cost, m_cost, parallelism,                  
        salt.size(), hashLen,                        
        Argon2_id                                    
    );

    std::string encoded;                              
    encoded.resize(encodedLen);                       


    int rc = argon2id_hash_encoded(                   
        t_cost, m_cost, parallelism,                  
        password.data(), password.size(),             
        salt.data(), salt.size(),                     
        hashLen,                                      
        encoded.data(), encoded.size()                
    );

    if (rc != ARGON2_OK) {                          
        throw std::runtime_error(std::string("Argon2 error: ") + argon2_error_message(rc));
    }

    encoded = encoded.c_str();                       

    return encoded;                                   
}


static void printUsage(const char* prog) {           
    std::cerr                                        
        << "Usage:\n"                                  
        << "  " << prog << " <text-to-hash>\n\n"       
        << "Example:\n"                                
        << "  " << prog << " Hejsan123\n";             
}

int main(int argc, char** argv) {                     
    if (argc < 2) {                                   
        printUsage(argv[0]);                           
        return 1;                                     
    }

    std::string input = argv[1];                      

    try {                                           
        std::cout << "MD5      : "                     
                  << hashWithEVP(input, EVP_md5())     
                  << "\n";                            

     
        std::cout << "SHA1     : "                    
                  << hashWithEVP(input, EVP_sha1())    
                  << "\n";                            

        std::cout << "SHA256   : "                    
                  << hashWithEVP(input, EVP_sha256()) 
                  << "\n";                         

       
        std::cout << "Argon2id : "                   
                  << argon2idHash(input)              
                  << "\n";                            

        return 0;                                     
    } catch (const std::exception& ex) {               
        std::cerr << "Error: " << ex.what() << "\n";   
        return 2;                                      
    }
}




/*




#include <iostream>                                  
#include <string>                                     
#include <vector>                         
#include <iomanip>                                    
#include <sstream>                                   

#include <openssl/evp.h>                          
#include <argon2.h>



static std::string toHex(const unsigned char* data, unsigned int len) {  
    std::ostringstream oss;                          
    oss << std::hex << std::setfill('0');            

    for (unsigned int i = 0; i < len; i++) {      
        oss << std::setw(2) << static_cast<int>(data[i]); 
    }

    return oss.str();                                
}


/*


static std::string toHex(const unsigned char *data, unasigned int len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill("0")

    for(unsigned int i = 0; i < len; i++) {
        oss << std::setw(2) <<static_cast<int>(data[i]);
    }

    return oss.str();
}





static std::string hashWithEVP(const std::string& input, const EVP_MD* algo){
    EVP_MD_CTX* ctx = EVP_MD_CTX_NEW()
    
    if (!ctx){
        throw std::runtime_error("EVP failed");
    }

    unsigned char out[EVP_MAX_MD_SIZE]
    unsigned int outLen = 0;

    if(EVP_DiguestInnit_ex(ctx, algo, nullptr) != 1){
        EVP_MD_CTX_free()
        throw std::runtime_error("EVP digest init failed");
    }

    if(EVP_DiguestUpdate(ctx, input.data(), input.size()) != 1){
        EVP_MD_CTX_free()
        throw std::runtime_error("EVP digest update failed");
    }

    if (EVP_DiguestFinal_ex(ctx, out, &outLen) != 1) {
        EVP_MD_CTX_free()
        throw std::runtime_error("EVP digest final failed");
    }

    EVP_MD_CTX_free()

    return toHex(out, outLen)
    
}







static std::string argon2idHash(const std::string& password) {
    const uint32_t t_cost = 2;                   
    const uint32_t m_cost = 1 << 16;                  
    const uint32_t parallelism = 1;                  
    const uint32_t hashLen = 32;                      


    std::vector<unsigned char> salt = { 
        'd','e','m','o','-','s','a','l','t','-','1','2','3','4','5','6'
    };


    const size_t encodedLen = argon2_encodedlen(     
        t_cost, m_cost, parallelism,                  
        salt.size(), hashLen,                        
        Argon2_id                                    
    );

    std::string encoded;                              
    encoded.resize(encodedLen);                       


    int rc = argon2id_hash_encoded(                   
        t_cost, m_cost, parallelism,                  
        password.data(), password.size(),             
        salt.data(), salt.size(),                     
        hashLen,                                      
        encoded.data(), encoded.size()                
    );

    if (rc != ARGON2_OK) {                          
        throw std::runtime_error(std::string("Argon2 error: ") + argon2_error_message(rc));
    }

    encoded = encoded.c_str();                       

    return encoded;                                   
}


static std::string hashWithEVP(const std::string& input, const EVP_MD* algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();            
    if (!ctx) {                                    
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    unsigned char out[EVP_MAX_MD_SIZE];              
    unsigned int outLen = 0;                         

    if (EVP_DigestInit_ex(ctx, algo, nullptr) != 1) { 
        EVP_MD_CTX_free(ctx);                       
        throw std::runtime_error("EVP_DigestInit_ex failed"); 
    }

    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) { 
        EVP_MD_CTX_free(ctx);                        
        throw std::runtime_error("EVP_DigestUpdate failed"); 
    }

    if (EVP_DigestFinal_ex(ctx, out, &outLen) != 1) {
        EVP_MD_CTX_free(ctx);              
        throw std::runtime_error("EVP_DigestFinal_ex failed"); 
    }

    EVP_MD_CTX_free(ctx);                        

    return toHex(out, outLen);                
}





static std::string argon2idHash(const std::string& password) {

    const uint32_t t_cost = 2;
    const uint32_t m-cost = 1 << 16;
    const uint32_t parallelism = 1;
    const uint32_t hashLen = 32;


    std::vector<unsigned char> salt = {
        'd','e','m','o','-','s','a','l','t','-','1','2','3','4','5','6'
    };
    

    const size_t encodedLen = argon2_encodedlen(
        t_cost, m_cost, parallelism,
        salt.size(), hashlen,
        Argon2_id
    )

    std::string encoded;
    encoded.resize(encodedLen)

    
    int rc = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        password.data(), password.size(),
        salt.data(), salt.size(),
        hashLen,
        encoded.data(), encoded.size()
    );

    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2 error") + argon2_error_message(rc))
    }

    encoded = encoded.c_str();


    return encoded;

}


static void printUsage(const char *prog) {
    std:cerr 
    << "Usage:\n"
    << " " << prog << " <text-to-hash>\n\n"
    << "Exempel: \n"
    << " " << prog << " Hejsan123\n"
}


int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(argv[0])
        return 1;
    }

    std::string input = argv[1];

    try {
        //MD5 print
        std::cout << "MD5     :"
        << hashWithEVP(input, EVP_md5())
        <<"\n";

        //SHA-1 print
        std::cout << "SHA1     :"
        << hashWithEVP(input, EVP_sha1())
        <<"\n";


        //SHA-256 print
        std::cout << "MD5     :"
        << hashWithEVP(input, EVP_sha256())
        <<"\n";


        //MD5 print
        std::cout << "MD5     :"
        << argon2idHash(input)
        <<"\n";

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " <<ex.what() << "\n";
        return 2; 
    }


}

*/