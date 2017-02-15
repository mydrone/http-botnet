// how to compile: g++ -std=c++11 file_name.cpp -L/usr/lib -lssl -lcrypto
// needed to encrypt msg for candc make sure XOR keys are the same
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <iostream>
using namespace std;
char key[10] = {'K', 'C', 'Q', '1', '3', 'F', 'Z', 'X', '2', '9'};
string base64_encode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
{
    BIO *base64_filter = BIO_new( BIO_f_base64() );
    BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
    BIO *bio = BIO_new( BIO_s_mem() );
    BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );
    bio = BIO_push( base64_filter, bio );
    BIO_write( bio, str.c_str(), str.length() );
    BIO_flush( bio );
    char *new_data;
    long bytes_written = BIO_get_mem_data( bio, &new_data );
    string result( new_data, bytes_written );
    BIO_free_all( bio );
    return result;
}

string base64_decode( const string &str ) // *possible memory leak* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
{
    BIO *bio, *base64_filter, *bio_out;
    char inbuf[512];
    int inlen;
    base64_filter = BIO_new( BIO_f_base64() );
    BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );
    bio = BIO_new_mem_buf( (void*)str.c_str(), str.length() );
    bio = BIO_push( base64_filter, bio );
    bio_out = BIO_new( BIO_s_mem() );
    while( (inlen = BIO_read(bio, inbuf, 512)) > 0 ){
        BIO_write( bio_out, inbuf, inlen );
    }
    BIO_flush( bio_out );
    char *new_data;
    long bytes_written = BIO_get_mem_data( bio_out, &new_data );
    string result( new_data, bytes_written );
    BIO_free_all( bio );
    BIO_free_all( bio_out );
    return result;
}

string encrypt_decrypt(string to_encrypt) // xor encryption/decryption
{
    string output = to_encrypt;
    for (int i = 0; i < to_encrypt.size(); i++)
    {
        output[i] = to_encrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];
    }
    return output;
}

int main()
{
    string display_key, input_string;
    for(int i = 0; i < sizeof(key); i++) 
    { 
        display_key += string("|") +  key[i];
    }
    display_key += string("|");
    cout << "Current XOR key: " << display_key << endl << "Enter string to encode and encrypt example: 'botid=all&recursive=yes&command=syscmd*touch /tmp/meme.txt': ";
    getline(cin, input_string);
    string base64_output = base64_encode(encrypt_decrypt(base64_encode(input_string)));
    cout << "Encrypted: " << base64_output << endl;
    string base64_input = base64_decode(encrypt_decrypt(base64_decode(base64_output)));
    cout << "Decrypted: " << base64_input << endl;
    return 0;
}