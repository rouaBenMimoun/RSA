#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pem2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int main()
{
    int A =0;
    char option;

    // Start a while loop that will continue as long as A is equal to 0

    while (A==0){
            //output menu in terminal
        printf("Please select an option:\n");
        printf("1. Encrypt data\n");
        printf("2. Decrypt data\n");
        printf("3. Generate, save and encrypt symmetric key\n");
        printf("4. decrypt symmetric key\n");
        printf("5. encrypt file\n");
        printf("6. decrypt file\n");
        printf("7. exit\n");

        fgets(&option, 100, stdin);

        if (option == '1') {

            // Task 1: RSA encryption

            // input of message to encrypt in variable data
            unsigned char data[256];
            printf("Enter message to encrypt: ");
            fgets(&data, 256, stdin);
            int data_len = strlen((char *)data);

            // read public key from file public_key.pem and store it into variable public_key
            FILE *public_key_file = fopen("public_key.pem", "r");
            RSA *public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
            fclose(public_key_file);

            //encryption of message using public key
            //and storing the result in variable encrypted_data
            unsigned char encrypted_data[256];
            int encrypted_data_len = RSA_public_encrypt(
                data_len, data, encrypted_data, public_key, RSA_PKCS1_PADDING);

            //output of encrypted message in file encrypted_data.bin
            FILE *encrypted_data_file = fopen("encrypted_data.bin", "wb");
            fwrite(encrypted_data, sizeof(unsigned char), encrypted_data_len, encrypted_data_file);
            fclose(encrypted_data_file);
            printf("message encrypted\n");

            system("pause");
        }


        else if (option == '2') {
            // Task 2: RSA decryption

            // read encrypted message from file encrypted_data.bin store it into variable encrypted_data
            unsigned char encrypted_data[256];
            FILE *encrypted_data_file = fopen("encrypted_data.bin", "rb");
            int encrypted_data_len = fread(encrypted_data, sizeof(unsigned char), 256, encrypted_data_file);
            fclose(encrypted_data_file);

            // read private key from file private_key.pem and store it into variable private_key
            unsigned char decrypted_data[256];
            FILE *private_key_file = fopen("private_key.pem", "r");
            RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
            fclose(private_key_file);

            //decryption of encrypted message using private key
            int decrypted_data_len = RSA_private_decrypt(
                encrypted_data_len, encrypted_data, decrypted_data, private_key, RSA_PKCS1_PADDING);

            //output of decrypted message in terminal
            decrypted_data[decrypted_data_len] = '\0';
            printf("Decrypted data: %s\n", decrypted_data);

            system("pause");
        }


        else if (option == '3') {
            // TASK 3 Generating Symmetric Key Part  1

            //Generating symmetric key and storing in a variable symmetric_key
            unsigned char symmetric_key[AES_BLOCK_SIZE];
            if (!RAND_bytes(symmetric_key, AES_BLOCK_SIZE)){
                printf("error generating:\n");
            }

            // read public key from file public_key.pem and store it into variable public_key
            FILE *public_key_file = fopen("public_key.pem", "r");
            RSA *public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
            fclose(public_key_file);

            //encryption of message using public key
            //and storing the result in variable encrypted_key
            unsigned char encrypted_key[2048];
            int encrypted_key_len = RSA_public_encrypt(
            AES_BLOCK_SIZE, symmetric_key, encrypted_key, public_key, RSA_PKCS1_PADDING);

            //output of symmetric key (not encrypted) in symmetric_key.bin to be used in further communication
            FILE *sym_key_file = fopen("symmetric_key.bin", "wb");
            fwrite(symmetric_key, sizeof(unsigned char), AES_BLOCK_SIZE, sym_key_file);
            fclose(sym_key_file);

            //output of symmetric key (encrypted) in encrypted_key.bin to be sent
            FILE *encrypted_key_file = fopen("encrypted_key.bin", "wb");
            fwrite(encrypted_key, sizeof(unsigned char), encrypted_key_len, encrypted_key_file);
            fclose(encrypted_key_file);

            system("pause");
        }


        else if (option == '4') {
            // TASK 3 Generating Symmetric Key Part  2

            // read encrypted key from file encrypted_key.bin store it into variable encrypted_key
            unsigned char encrypted_key[2048];
            FILE *encrypted_key_file = fopen("encrypted_key.bin", "rb");
            int encrypted_key_len = fread(encrypted_key, sizeof(unsigned char), 1024, encrypted_key_file);
            fclose(encrypted_key_file);

            // read private key from file private_key.pem and store it into variable private_key
            FILE *private_key_file = fopen("private_key.pem", "r");
            RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
            fclose(private_key_file);


            //decryption of encrypted key using private key
            unsigned char decrypted_key[AES_BLOCK_SIZE];
            int decrypted_key_len = RSA_private_decrypt(
                encrypted_key_len, encrypted_key, decrypted_key, private_key, RSA_PKCS1_PADDING);

            //output decrypted symmetric key into file symmetric_key.bin
            decrypted_key[decrypted_key_len] = '\0';
            FILE *sym_key_file = fopen("symmetric_key.bin", "wb");
            fwrite(decrypted_key, sizeof(unsigned char), AES_BLOCK_SIZE, sym_key_file);
            fclose(sym_key_file);

            system("pause");
        }


        else if (option == '5') {
            //Task 4 Symmetric encryption of large data file

            //opening input and output files
                        FILE* input_file = fopen("file.txt", "rb");
            FILE* output_file = fopen("codedfile.bin", "wb");

            //reading symmetric key from file symmetric_key.bin
            unsigned char key[AES_BLOCK_SIZE];
            FILE* key_file = fopen("symmetric_key.bin", "rb");
            fread(key, sizeof(unsigned char), AES_BLOCK_SIZE, key_file);
            fclose(key_file);

            // encryption of file block by block
            AES_KEY aes_key;
            AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);
            unsigned char input_block[AES_BLOCK_SIZE];
            unsigned char output_block[AES_BLOCK_SIZE];
            int bytes_read;
            while ((bytes_read = fread(input_block, sizeof(unsigned char), AES_BLOCK_SIZE, input_file)) > 0) {
                AES_encrypt(input_block, output_block, &aes_key);
                fwrite(output_block, sizeof(unsigned char), bytes_read, output_file);
            }
            //Closing input and output files
            fclose(input_file);
            fclose(output_file);

            system("pause");
        }


        else if (option == '6') {
            //Task 5 Symmetric decryption od

            //opening input and output files
            FILE* input_file = fopen("codedfile.bin", "rb");
            FILE* output_file = fopen("decryptedfile.txt", "wb");

            //reading symmetric key from file symmetric_key.bin
            unsigned char key[AES_BLOCK_SIZE];
            FILE* key_file = fopen("symmetric_key.bin", "rb");
            fread(key, sizeof(unsigned char), AES_BLOCK_SIZE, key_file);
            fclose(key_file);

            // encryption of file block by block
            AES_KEY aes_key;
            AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &aes_key);
            unsigned char input_block[AES_BLOCK_SIZE];
            unsigned char output_block[AES_BLOCK_SIZE];
            int bytes_read;
            while ((bytes_read = fread(input_block, sizeof(unsigned char), AES_BLOCK_SIZE, input_file)) > 0) {
                AES_decrypt(input_block, output_block, &aes_key);
                fwrite(output_block, sizeof(unsigned char), bytes_read, output_file);

            }

            //Closing input and output files
            fclose(input_file);
            fclose(output_file);

            system("pause");
        }


        else if (option == '7') {
            //exit the while loop
            A=1;
        }


        else{
            printf("Invalid option:\n");
        }

    }

    return 0;
}
