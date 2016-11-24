#pragma once

#include <string>

#define KEY_PATH ".//keys//key.test"
#define KEY_SIGN_PATH ".//keys//keysig.test"

typedef enum CryptoKeyGenerateLevel
{
    CKGL_LOW = 1,
    CKGL_HIGH = 2,
};

typedef enum ChatCodeTypes
{
	CCT_NOP = 0,
    CCT_TDES = 1,
    CCT_AES = 2
};

typedef enum ChatCodeSignTypes
{
	CCST_NOP = 0,
	CCST_ECDSA = 1
};

typedef enum ChatSecurityType
{
	CST_NONE = 0,
	CST_CIPHER = 1,
	CST_SIGN = 2
};

#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <map>
#include <vector>

// Кодер для данных
class DataCoder
{
	std::map<int, int> codeType;
    std::string basicData;
	unsigned char* byteDataPtr;
	size_t byteDataLength;
    static std::string certName;
    EC_KEY* pubkey, *eckey;
public:
    DataCoder(void);
    virtual ~DataCoder(void);
    std::string toEncodedString(int securityType);
    std::string toDecodedString(int securityType);
    bool genKeyComplect(std::string &fileName, CryptoKeyGenerateLevel level);
	static void setSertificatePath(std::string &path);
    static std::string getSertificatePath()
    {
        return certName;
    }

	void assign(unsigned char* ptr, size_t length)
	{
		if(length <= 0)
			return;
		else
			byteDataLength = length;

		if(byteDataPtr != NULL)
			delete []byteDataPtr;

		byteDataPtr = new unsigned char[length];
		memset(byteDataPtr, 0, length);

		do{byteDataPtr[length - 1] = ptr[length - 1];}while(--length);
	}

    void assign(std::string str)
    {
        basicData = str;
    }
	size_t byteDataSize()
	{
		return byteDataLength;
	}
    size_t size()
    {
        return basicData.size();
    }
};

// Генератор ключей

class TGeneralKeyGenerator
{
public:

	// --- Функция для рандомной генерации ключей ---
	// Параметр keySize определяет длинну ключа в битах, следовательно он должен быть кратным 8
	static bool generateRandomKeys(std::string &filename, CryptoKeyGenerateLevel level, size_t keySize);
};

// Данный кодер осуществляет шифрование/дешифрование по алгоритму DES
class TDESCipher
{
public:
    static std::string cryptData(std::string &input);
    static std::string decryptData(std::string &input);
    static bool generateRandomKeys(std::string &fileName, CryptoKeyGenerateLevel level);
};

// Данный кодер осуществляет шифрование/дешифрование по алгоритму AES
class TAESCipher
{
public:
    static std::string cryptData(std::string &input);
    static std::string decryptData(std::string &input);
	static bool generateRandomKeys(std::string &fileName, CryptoKeyGenerateLevel level);
};

class TECDSASigner
{
public:
	static std::string signData(std::string &input, EC_KEY* pubkey);
	static bool verifyData(std::string &input, std::string &output, EC_KEY* pubkey);
};