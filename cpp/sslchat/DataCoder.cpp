#include "StdAfx.h"

#include <openssl/pem.h>

DataCoder::DataCoder(void)
: byteDataLength(0), byteDataPtr(NULL), pubkey(NULL), eckey(NULL)
{
    // Для тестовых целей устанавливаем значение типа кодирования в конструкторе 

	codeType[CST_CIPHER] = CCT_AES;
	codeType[CST_SIGN] = CCST_ECDSA;

    FILE *keyFP = fopen(KEY_SIGN_PATH, "r");

	if (keyFP == NULL)
		return;

	// Освобождаем старый экземпляр ключа
	if (eckey != NULL) 
    {
		EC_KEY_free(eckey);
		eckey = NULL;
	}

    char pswd[] = "1234";
	eckey = PEM_read_ECPrivateKey(keyFP, NULL, NULL, pswd);

	fclose(keyFP);

	if (eckey == NULL)
		return;

    if(DataCoder::getSertificatePath().size() > 0)
    {
        FILE *certFP = fopen(DataCoder::getSertificatePath().c_str(), "r");

	    if (certFP == NULL)
		    return;

    	X509 *cert = PEM_read_X509(certFP, NULL, NULL, NULL);
    
	    fclose(certFP);

    	if (cert == NULL)
	    	return;

    	EVP_PKEY *pkey = X509_get_pubkey(cert);

	    X509_free(cert);

    	if (pkey == NULL)
	    	return;

	    // Освобождаем старый экземпляр сертификата
    	if (pubkey != NULL) {
	    	EC_KEY_free(pubkey);
		    pubkey = NULL;
    	}

	    pubkey = EVP_PKEY_get1_EC_KEY(pkey);

    	EVP_PKEY_free(pkey);

	    if (pubkey == NULL)
	    	return;
    }
}   

DataCoder::~DataCoder(void)
{
	if(byteDataLength > 0 || byteDataPtr != NULL)
	{
		delete[] byteDataPtr;
		byteDataPtr = NULL;
		byteDataLength = 0;
	}

    if(pubkey != NULL)
    {
        EC_KEY_free(pubkey);
		    pubkey = NULL;
    }

    if (eckey != NULL) 
    {
		EC_KEY_free(eckey);
		eckey = NULL;
	}
}
std::string DataCoder::toEncodedString(int securityType)
{
	if(securityType == CST_NONE)
		return basicData;

	std::string woSignature;

	if(securityType & CST_CIPHER)
	{
		if(codeType[CST_CIPHER] == CCT_TDES)
		    woSignature = TDESCipher::cryptData(basicData);

		else if(codeType[CST_CIPHER] == CCT_AES)
			woSignature = TAESCipher::cryptData(basicData);

		else woSignature = basicData;
	}
	if(securityType & CST_SIGN)
	{
		if(codeType[CST_SIGN] == CCST_ECDSA)
			return TECDSASigner::signData(woSignature, eckey);
		else
			return woSignature;
	}
    else
        return woSignature;
}
std::string DataCoder::toDecodedString(int securityType)
{
	if(securityType == CST_NONE)
        return basicData;

	std::string woSignature;

	if(securityType & CST_SIGN)
	{
		if(codeType[CST_SIGN] == CCST_ECDSA)
		{
			if(TECDSASigner::verifyData(basicData, woSignature, pubkey) == false)
				return basicData;
		}
		else
			woSignature = basicData;

	}
	else
		woSignature = basicData;
	if(securityType & CST_CIPHER)
	{
		if(codeType[CST_CIPHER] == CCT_TDES)
			return TDESCipher::decryptData(woSignature);

		else if(codeType[CST_CIPHER] == CCT_AES)
			return TAESCipher::decryptData(woSignature);

		else
			return basicData;
	}
	else
		return basicData;
}

bool DataCoder::genKeyComplect(std::string &fileName, CryptoKeyGenerateLevel level)
{
    if(codeType[CST_CIPHER] == CCT_TDES)
        return TDESCipher::generateRandomKeys(fileName, level);

	else if (codeType[CST_CIPHER] == CCT_AES)
		return TAESCipher::generateRandomKeys(fileName, level);

    else
        return false;
}

std::string DataCoder::certName;

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/des.h>

void DataCoder::setSertificatePath(std::string &path)
{
    certName.assign(path.c_str());
}

/*
    Алгоритм формирования ЭЦП: ECDSA.
    Алгоритм формирования ХЭШ: sha-256
*/
std::string TECDSASigner::signData(std::string &input, EC_KEY* eckey)
{
    if(eckey == NULL)
    	return input;
    else
    {
        int signSizeByType = ECDSA_size(eckey);

        assert(input.c_str() != NULL);
        assert(input.size() > 0);

    	// Вычисляем хэш
	    int digestLen = SHA256_DIGEST_LENGTH;
	    unsigned char *digest = new unsigned char[digestLen];
        assert(digest != NULL);

        SHA256_CTX context;

	    SHA256_Init(&context);
	    SHA256_Update(&context, input.c_str(), input.size());
	    SHA256_Final(digest, &context);

    	ECDSA_SIG *sig = ECDSA_do_sign(digest, digestLen, eckey);

	    delete [] digest;

    	if (sig == NULL)
	    	return input;

        unsigned char *res = new unsigned char[digestLen];
        memset(res, 0, digestLen);

    	// Преобразуем подпись из внутреннего представления в массив байт
	    int signSize = i2d_ECDSA_SIG(sig, &res);

	    // Подчищаемся
    	ECDSA_SIG_free(sig);

    	if (signSize <= 0)
        {
            delete[] res;
	    	return input;
        }

        std::string out;
        out.assign((const char*)res, signSize);

        delete[] res;

        return out;
    }
}
bool TECDSASigner::verifyData(std::string &input, std::string &output, EC_KEY* pubkey)
{
    if(pubkey == NULL)
        return false;

	return true;
}

bool TGeneralKeyGenerator::generateRandomKeys(std::string &fileName, CryptoKeyGenerateLevel level, size_t keySize)
{
	FILE* f = NULL;

    f = fopen(fileName.c_str(), "a+");

    assert(f != NULL);

    if(level == CKGL_LOW)
    {
        DES_cblock cb;
        DES_key_schedule ks;
           
        for(size_t i = 0; i < keySize/8; i ++)
        {
            DES_random_key(&cb);
    
            if(DES_set_key_checked(&cb, &ks) != 0)
            {
                fclose(f);
                return false;
            }

            if(fwrite(&ks, DES_SCHEDULE_SZ, 1, f) <= 0)
            {
                fclose(f);
                return false;
            }
        }
    }
    else
    {
        DES_cblock cb;

        for(size_t i = 0; i < keySize/8; i ++)
        {
            DES_random_key(&cb);

            if(fwrite(&cb, sizeof(DES_cblock), 1, f) <= 0)
            {
                fclose(f);
                return false;
            }
        }
    }
    fclose(f);
    return true;
}

bool TDESCipher::generateRandomKeys(std::string &fileName, CryptoKeyGenerateLevel level)
{
	return TGeneralKeyGenerator::generateRandomKeys(fileName, level, 24);
}

std::string TDESCipher::cryptData(std::string &input)
{
    //unsigned char kss[24] = {1,2,3,4,2,3,4,5,3,4,5,6,4,5,6,7,9,8,7,6,8,7,6,5};
    unsigned char kss[24] = {0};

    FILE* f = NULL;

    f = fopen(std::string(KEY_PATH).c_str(), "r+b");

    assert(f != NULL);

    fseek(f, 0, SEEK_SET);

    if(fread(kss, sizeof(char), 24, f) <= 0)
    {
       fclose(f);
       return std::string();
    }

    fclose(f);

    unsigned char *ptr =  (unsigned char*)input.c_str(), *ptrRet = new unsigned char[input.size()];

    assert(ptrRet != NULL);

    memset(ptrRet, 0, input.size());

    unsigned char iv[8] = {0,0,0,0,0,0,0,0};

    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX_init(&ctx);

    cipher = EVP_des_ecb();

    EVP_EncryptInit(&ctx, cipher, kss, iv);

    std::string sRet;

    int outlen = 0;

    if(!EVP_EncryptUpdate(&ctx, ptrRet, &outlen, ptr, (int)input.size()))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }
    sRet.append((char*)ptrRet, outlen);

    memset(ptrRet, 0, input.size());

    int oldOutlen = outlen;

    if(!EVP_EncryptFinal(&ctx, ptrRet, &outlen))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }

    //sRet.append((char*)ptrRet, input.size() - oldOutlen);

    sRet.append((char*)ptrRet, outlen);

    if(ptrRet != NULL)
        delete[] ptrRet;

    EVP_CIPHER_CTX_cleanup(&ctx);

    return sRet;
}

std::string TDESCipher::decryptData(std::string &input)
{
    //unsigned char kss[24] = {1,2,3,4,2,3,4,5,3,4,5,6,4,5,6,7,9,8,7,6,8,7,6,5};
    unsigned char kss[24] = {1};

    FILE* f = NULL;

    f = fopen(std::string(KEY_PATH).c_str(), "r+b");

    assert(f != NULL);

    fseek(f, 0, SEEK_SET);

    if(fread(kss, sizeof(char), 24, f) <= 0)
    {
       fclose(f);
       return std::string();
    }

    fclose(f);

    std::string tmpInput = input;

    unsigned char *ptr =  (unsigned char*)tmpInput.c_str(), 
        *ptrRet = new unsigned char[tmpInput.size()];

    assert(ptrRet != NULL);

    memset(ptrRet, 0, tmpInput.size());

    unsigned char iv[8] = {0,0,0,0,0,0,0,0};

    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX_init(&ctx);

    cipher = EVP_des_ecb();

    EVP_DecryptInit(&ctx, cipher, kss, iv);

    std::string sRet;

    int outlen = 0;

    if(!EVP_DecryptUpdate(&ctx, ptrRet, &outlen, ptr, (int)tmpInput.size()))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }
    sRet.append((char*)ptrRet, outlen);

    memset(ptrRet, 0, tmpInput.size());

    if(!EVP_DecryptFinal(&ctx, ptrRet, &outlen))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }

    sRet.append((char*)ptrRet, outlen);

    if(ptrRet != NULL)
        delete[] ptrRet;

    EVP_CIPHER_CTX_cleanup(&ctx);

    return sRet;
}

bool TAESCipher::generateRandomKeys(std::string &fileName, CryptoKeyGenerateLevel level)
{
	return TGeneralKeyGenerator::generateRandomKeys(fileName, level, 32);
}

std::string TAESCipher::cryptData(std::string &input)
{
	
	//EVP_CIPHER a;
	//EVP_aes_256_cfb;
	//unsigned char kss[32] = {1,1,1,1,1,1,1,1,1,9,8,7,6,5,6,7,8,9,5,4,3,2,1,2,3,4,5,6,7,6,5,1};
	unsigned char kss[32] = {1};
	//unsigned char iv[] = {1,2,3,4,5,6,7,8};

	FILE* f = NULL;

    f = fopen(std::string(KEY_PATH).c_str(), "r+b");

    assert(f != NULL);

    fseek(f, 0, SEEK_SET);

    if(fread(kss, sizeof(char), 32, f) <= 0)
    {
       fclose(f);
       return std::string();
    }

    fclose(f);	

	unsigned char *ptr =  (unsigned char*)input.c_str(), *ptrRet = new unsigned char[input.size()];

    assert(ptrRet != NULL);

    memset(ptrRet, 0, input.size());

    unsigned char iv[8] = {0,0,0,0,0,0,0,0};

    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX_init(&ctx);

    cipher = EVP_aes_256_cfb();

    EVP_EncryptInit(&ctx, cipher, kss, iv);

    std::string sRet;

    int outlen = 0;

    if(!EVP_EncryptUpdate(&ctx, ptrRet, &outlen, ptr, (int)input.size()))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }
    sRet.append((char*)ptrRet, outlen);

    memset(ptrRet, 0, input.size());

    int oldOutlen = outlen;

    if(!EVP_EncryptFinal(&ctx, ptrRet, &outlen))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }

    //sRet.append((char*)ptrRet, input.size() - oldOutlen);

    sRet.append((char*)ptrRet, outlen);

    if(ptrRet != NULL)
        delete[] ptrRet;

    EVP_CIPHER_CTX_cleanup(&ctx);

    return sRet;
	
}

std::string TAESCipher::decryptData(std::string &input)
{
	//unsigned char kss[32] = {1,1,1,1,1,1,1,1,1,9,8,7,6,5,6,7,8,9,5,4,3,2,1,2,3,4,5,6,7,6,5,1};

	unsigned char kss[32] = {1};

	FILE* f = NULL;

    f = fopen(std::string(KEY_PATH).c_str(), "r+b");

    assert(f != NULL);

    fseek(f, 0, SEEK_SET);

    if(fread(kss, sizeof(char), 32, f) <= 0)
    {
       fclose(f);
       return std::string();
    }

    fclose(f);

	std::string tmpInput = input;

    unsigned char *ptr =  (unsigned char*)tmpInput.c_str(), 
        *ptrRet = new unsigned char[tmpInput.size()];

    assert(ptrRet != NULL);

    memset(ptrRet, 0, tmpInput.size());

    unsigned char iv[8] = {0,0,0,0,0,0,0,0};

    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX_init(&ctx);

    cipher = EVP_aes_256_cfb();

    EVP_DecryptInit(&ctx, cipher, kss, iv);

    std::string sRet;

    int outlen = 0;

    if(!EVP_DecryptUpdate(&ctx, ptrRet, &outlen, ptr, (int)tmpInput.size()))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }
    sRet.append((char*)ptrRet, outlen);

    memset(ptrRet, 0, tmpInput.size());

    if(!EVP_DecryptFinal(&ctx, ptrRet, &outlen))
    {
        if(ptrRet != NULL)
            delete[] ptrRet;
        return std::string("-1");
    }

    sRet.append((char*)ptrRet, outlen);

    if(ptrRet != NULL)
        delete[] ptrRet;

    EVP_CIPHER_CTX_cleanup(&ctx);

    return sRet;
}