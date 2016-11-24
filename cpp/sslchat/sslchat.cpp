// sslchat.cpp: определяет точку входа для консольного приложения.
//
#include "stdafx.h"
#include <winsock.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <conio.h>


// Умолчания
#define DEFAULT_USER "defaultUser"
#define DEFAULT_PORT 5555
#define DEFAULT_IP "127.0.0.255"

// Настройки транспорта для сообщений
#define SPECIAL_DATA_SIZE 5

// Настройки смещений
#define STX_OFFSET 0
#define LENGTH_OFFSET 1
#define DATA_OFFSET 3

// Начало пакета
#define STX 0x06

// Класс, описывающий атомарный пакет сетевого транспорта
class ChatAtomPacket
{
#define  CRC16    0xA001

	DataCoder data;
	unsigned char* packet;
protected:
	void clearPacket()
	{
		if(packet != NULL)
		{
			delete []packet;
			packet = NULL;
		}
	}
	unsigned short calculateCRC(unsigned char* data, size_t length)
	{
		unsigned short ret = CRC16;

		for(size_t sz = 0; sz < length; sz ++)
			ret += data[sz];

		return ret;
	}
public:
	ChatAtomPacket()
		: packet(NULL)
	{}

	ChatAtomPacket(std::string _data)
		: packet(NULL)
	{
        data.assign(_data);

		if(_data.size() > 0)
            makePacket(data.toEncodedString(CST_CIPHER | CST_SIGN));
	}
	virtual ~ChatAtomPacket()
	{
		clearPacket();
	}
	bool makePacket(std::string _data)
	{
		if(_data.size() <= SPECIAL_DATA_SIZE)
			return false;

		clearPacket();

		size_t size = _data.size() + SPECIAL_DATA_SIZE;	

		packet = new unsigned char[size + 1];
		memset(packet, 0, size + 1);

		assert(packet != NULL);

		packet[STX_OFFSET] = STX;
		packet[LENGTH_OFFSET] = (unsigned char)((size >> 8) & 0xff);
		packet[LENGTH_OFFSET + 1] = (unsigned char)(size & 0xff);
		
		for(size_t i = 0; i < _data.size(); i ++)
			packet[DATA_OFFSET + i] = _data.c_str()[i];

		unsigned short crc = calculateCRC(packet, SPECIAL_DATA_SIZE + _data.size() - 2);

		packet[DATA_OFFSET + _data.size()] = ((crc >> 8) & 0xff);
		packet[DATA_OFFSET + _data.size() + 1] = crc &0xff;

        data.assign(_data);

		return true;
	}
	bool parsePacket(unsigned char* _packet)
	{
		if(_packet == NULL)
			return false;

		if(_packet[STX_OFFSET] != STX)
			return false;

		size_t sz = ((_packet[LENGTH_OFFSET] << 8) & 0xff00) + (_packet[LENGTH_OFFSET + 1] & 0xff);

		if(sz <= 0)
			return false;

		unsigned short crcCalculated = 0, crcObtained = 0;

		crcObtained = ((_packet[sz - 2] << 8) & 0xff00) + (_packet[sz - 1] & 0xff);

		crcCalculated = calculateCRC(_packet, sz - 2);

		if(crcCalculated != crcObtained)
			return false;

        std::string tmpData;

		for(size_t i = 0; i < sz - SPECIAL_DATA_SIZE; i ++)
			tmpData += _packet[DATA_OFFSET + i];

        data.assign(tmpData);

		return true;
	}
	const unsigned char* getCurrentPacket()
	{
		return packet;
	}
	size_t packetSize()
	{
		return data.size() + SPECIAL_DATA_SIZE;
	}
	std::string getCurrentData()
	{
		return data.toDecodedString(CST_CIPHER | CST_SIGN);
	}
};
// Тип callback-функции для вывода полученных сообщений
typedef int (* callBackType)(ChatAtomPacket &);
// Вспомогательный элемент для работы с разными кодовыми страницами
class CodePageManager
{
    char* insidePtr;
public:
    typedef enum CodePageTypes
    {
        CPT_OEM = 1,
        CPT_CHAR = 2
    };

    CodePageManager(char* _pStr, CodePageTypes _basic)
        : insidePtr(NULL)
    {
        switch(_basic)
        {
        case CPT_OEM:
            insidePtr = new char[strlen(_pStr) + 1];
            memset(insidePtr, 0, strlen(_pStr) + 1);

            OemToCharA(_pStr, (LPSTR)insidePtr);
            break;
        case CPT_CHAR:
            insidePtr = new char[strlen(_pStr) + 1];
            memset(insidePtr, 0, strlen(_pStr) + 1);

            CharToOemA(_pStr, (LPSTR)insidePtr);
            break;
        }
    }
    CodePageManager(std::string _str, CodePageTypes _basic)
        : insidePtr(NULL)
    {
        switch(_basic)
        {
        case CPT_OEM:
            insidePtr = new char[_str.size() + 1];
            memset(insidePtr, 0, _str.size() + 1);

            OemToCharA(_str.c_str(), (LPSTR)insidePtr);
            break;
        case CPT_CHAR:
            insidePtr = new char[_str.size() + 1];
            memset(insidePtr, 0, _str.size() + 1);

            CharToOemA(_str.c_str(), (LPSTR)insidePtr);
            break;
        }
    }
    virtual ~CodePageManager()
    {
        if(insidePtr != NULL)
            delete[] insidePtr;
    }
    std::string stringValue()
    {
        std::string str;
        if(insidePtr != NULL)
            str.assign(insidePtr);
        return str;
    }
};
// Функция вывода сообщений в чате
void printLine(std::string str_, bool bDown = true)
{
    std::cout << CodePageManager(str_, CodePageManager::CPT_CHAR).stringValue();

    if(bDown == true)
        std::cout << std::endl;
}
// Интерфейс для сетевого компонента
class INetOperator
{
    static bool bInitedWSA;
public:
	virtual bool waitForInputPacket() = 0;
	virtual bool sendOutputPacket(std::string &_ip, ChatAtomPacket &packet) = 0;
    bool isInitedWSA(){return bInitedWSA;}
    void setInitedWSA(bool bInited){bInitedWSA = bInited;}
};

bool INetOperator::bInitedWSA = false;

// Реализация сетевого TCP компонента
class NetOperatorTCP
    : public INetOperator
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    HANDLE hWaitThread;

    unsigned int port;
    void *callBackPrinter;

    static NetOperatorTCP* pSelf;
public:
    NetOperatorTCP(void* pCallBack, unsigned int defaultPort)
        : hWaitThread(INVALID_HANDLE_VALUE), callBackPrinter(pCallBack), port(defaultPort)
	{
        if(isInitedWSA() == false)
        {
    		wVersionRequested = MAKEWORD(2, 2);

	    	err = WSAStartup(wVersionRequested, &wsaData);
		
		    assert(err == 0);

    		assert((LOBYTE(wsaData.wVersion) == 2 && HIBYTE(wsaData.wVersion) == 2));

            setInitedWSA(true);
        }

		printLine ("Сеть инициализирована\r\n");

        pSelf = this;
	}
	virtual ~NetOperatorTCP()
	{
		if(hWaitThread != INVALID_HANDLE_VALUE && hWaitThread != NULL)
			TerminateThread(hWaitThread, 0);

        if(isInitedWSA() == true)
        {
		    WSACleanup();

            setInitedWSA(false);
        }
	}

    bool waitForInputPacket()
	{
		hWaitThread = (HANDLE)_beginthread(&NetOperatorTCP::thrWaitFunction, 0, (LPVOID)callBackPrinter);

		if(hWaitThread == INVALID_HANDLE_VALUE || hWaitThread == NULL)
			return false;
		else
			return true;
	}
    bool sendOutputPacket(std::string &_ip, ChatAtomPacket &packet)
	{
		SOCKET SendSocket = socket(AF_INET, SOCK_STREAM, 0); // Создание сокета

		sockaddr_in local_addr;
		local_addr.sin_family=AF_INET;
        local_addr.sin_addr.s_addr=inet_addr(_ip.c_str());
		local_addr.sin_port=htons(port);

		sendto(SendSocket, (const char*)packet.getCurrentPacket(), (int)packet.packetSize(), 0, (SOCKADDR *)&local_addr, sizeof(local_addr)); // Отсылка пакета

		closesocket(SendSocket); // Закрытие сокета

		return true;
	}
	static void thrWaitFunction(void* param)
	{
        if(pSelf == NULL)
        {
            printLine("Не создан сетевой компонент");
            return;
        }
        do
        {
            callBackType cbt = (callBackType&)param;

            SOCKET sd = socket (AF_INET, SOCK_STREAM, 0);
 
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(pSelf->port);
            addr.sin_addr.s_addr = htonl(INADDR_ANY);;
 
            bind (sd, (sockaddr*)&addr, sizeof sockaddr_in);
 
            char buff[1024] = {0};
            int notUsed = sizeof sockaddr_in;
 
            //DWORD val = 6000;
            //setsockopt (sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&val, sizeof DWORD); //без этого вызова висим вечно

            int len=1;
            setsockopt(sd,SOL_SOCKET,SO_BROADCAST,(const char*)&len,sizeof(len));

            int iRet = 0;

            do
            {
                iRet = recvfrom (sd, buff, 1024, 0, (sockaddr*)&addr, &notUsed);
            }while(iRet == SOCKET_ERROR);

            char buf[128];
            hostent *h;

            if (gethostname(buf, 128) == 0)
            {
                h = gethostbyname(buf);
                if (h == NULL)
                {
                    closesocket(sd);
                    return;
                }
            }

            if(addr.sin_addr.s_addr == inet_addr(inet_ntoa (*(reinterpret_cast<in_addr *>(*(h->h_addr_list))))))
            {
                closesocket(sd);
                continue;
            }

            closesocket(sd);

            ChatAtomPacket cap;

            if(cap.parsePacket((unsigned char*)buff) == false)
                continue;

            (*cbt)(cap);
        }while(1);
    }
};

NetOperatorTCP* NetOperatorTCP::pSelf;

// Реализация сетевого UDP компонента
class NetOperatorUDP
	: public INetOperator
{
	HANDLE hWaitThread;

	WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    unsigned int port;
    void *callBackPrinter;

    static NetOperatorUDP* pSelf;
public:
	NetOperatorUDP(void* pCallBack, unsigned int defaultPort)
        : hWaitThread(INVALID_HANDLE_VALUE), callBackPrinter(pCallBack), port(defaultPort)
	{
        if(isInitedWSA() == false)
        {
    		wVersionRequested = MAKEWORD(2, 2);

	    	err = WSAStartup(wVersionRequested, &wsaData);
		
		    assert(err == 0);

    		assert((LOBYTE(wsaData.wVersion) == 2 && HIBYTE(wsaData.wVersion) == 2));

            setInitedWSA(true);

        }
		printLine ("Сеть инициализирована\r\n");

        pSelf = this;
	}
	virtual ~NetOperatorUDP()
	{
		if(hWaitThread != INVALID_HANDLE_VALUE && hWaitThread != NULL)
			TerminateThread(hWaitThread, 0);

        if(isInitedWSA() == true)
        {
		    WSACleanup();

            setInitedWSA(false);
        }
	}
	bool waitForInputPacket()
	{
		hWaitThread = (HANDLE)_beginthread(&NetOperatorUDP::thrWaitFunction, 0, (LPVOID)callBackPrinter);

		if(hWaitThread == INVALID_HANDLE_VALUE || hWaitThread == NULL)
			return false;
		else
			return true;
	}
    bool sendOutputPacket(std::string &_ip, ChatAtomPacket &packet)
	{
		SOCKET SendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // Создание сокета

		int on=1;

		sockaddr_in local_addr;
		local_addr.sin_family=AF_INET;
        local_addr.sin_addr.s_addr=inet_addr(_ip.c_str());
		local_addr.sin_port=htons(port);

		setsockopt(SendSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(on)); // Установка флага

		sendto(SendSocket, (const char*)packet.getCurrentPacket(), (int)packet.packetSize(), 0, (SOCKADDR *)&local_addr, sizeof(local_addr)); // Отсылка пакета

		closesocket(SendSocket); // Закрытие сокета

		return true;
	}
	static void thrWaitFunction(void* param)
	{
        if(pSelf == NULL)
        {
            printLine("Не создан сетевой компонент");
            return;
        }
        do
        {
            SOCKET sd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
 
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(pSelf->port);
            addr.sin_addr.s_addr = htonl(INADDR_ANY);;
 
            bind (sd, (sockaddr*)&addr, sizeof sockaddr_in);
 
            char buff[1024] = {0};
            int notUsed = sizeof sockaddr_in;
 
            //DWORD val = 6000;
            //setsockopt (sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&val, sizeof DWORD); //без этого вызова висим вечно

            int len=1;
            setsockopt(sd,SOL_SOCKET,SO_BROADCAST,(const char*)&len,sizeof(len));

            int iRet = 0;

            do
            {
                iRet = recvfrom (sd, buff, 1024, 0, (sockaddr*)&addr, &notUsed);
            }while(iRet == SOCKET_ERROR);

            char buf[128];
            hostent *h;

            if (gethostname(buf, 128) == 0)
            {
                h = gethostbyname(buf);
                if (h == NULL)
                {
                    closesocket(sd);
                    return;
                }
            }

            if(addr.sin_addr.s_addr == inet_addr(inet_ntoa (*(reinterpret_cast<in_addr *>(*(h->h_addr_list))))))
            {
                closesocket(sd);
                continue;
            }

            closesocket(sd);

            ChatAtomPacket cap;

            if(cap.parsePacket((unsigned char*)buff) == false)
                continue;

            callBackType cbt = (callBackType&)param;

            (*cbt)(cap);
        }while(1);
    }
};
NetOperatorUDP* NetOperatorUDP::pSelf = NULL;

#include <algorithm>

// Класс для перечисления всех файлов в дирректории
class FileEnumerator
{
    std::string dirPath;
    std::vector<std::string> files;
    bool success;
    bool getFileNames()
    {
        WIN32_FIND_DATAA ffd;
        HANDLE hFind;

        if(MAX_PATH <= dirPath.size())
            return false;

        char szFind[MAX_PATH*4] = {0};
        sprintf_s(szFind, MAX_PATH*4, "%s\\*", dirPath.c_str());

        hFind = FindFirstFileA(szFind, &ffd);

        if(hFind == INVALID_HANDLE_VALUE || hFind == NULL)
            return false;

        do
        {
            if(!(!strcmp(ffd.cFileName, ".") || !strcmp(ffd.cFileName, "..")))
                files.push_back(ffd.cFileName);
        }
        while(FindNextFileA(hFind, &ffd));

        FindClose(hFind);

        return true;
    }
public:
    FileEnumerator(std::string _dirPath)
        : dirPath(_dirPath), success(false)
    {
        success = getFileNames();

    }
    ~FileEnumerator(){}
    std::vector<std::string> maskedFiles(std::string mask = "")
    {
        std::vector<std::string> masked;

        if(success == false)
            return masked;

        std::vector<std::string>::iterator it = files.begin();
        for(; it != files.end(); it ++)
        {
            if(strstr((*it).c_str(), mask.c_str()) == (*it).c_str())
                masked.push_back((*it).c_str());
        }
        return masked;
    }
};

// Класс для всплывающих подсказок в консоле 
class ConsoleProcessor
{
    std::vector<std::string> prompts;
protected:
    void clearCurrentSymbol()
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        csbi.dwCursorPosition.X-=1;
        // получаем координаты строки для очистки
        COORD coord = {csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y};
        // заполняем строку пробелами
        FillConsoleOutputCharacter(hStdOut, ' ', 1, coord, NULL);
        // сбрасываем позицию курсора
        SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
    }
    void clearRowRight(int row, size_t value)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        // получаем координаты строки для очистки
        COORD coord = {csbi.dwCursorPosition.X - (short)value, row - 1};
        // заполняем строку пробелами
        FillConsoleOutputCharacter(hStdOut, ' ', 80 - csbi.dwCursorPosition.X + (DWORD)value, coord, NULL);
        // сбрасываем позицию курсора
        csbi.dwCursorPosition = coord;
        SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
    }
    void clearRow (int row)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем координаты строки для очистки
        COORD coord = {0, row - 1};
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        // заполняем строку пробелами
        FillConsoleOutputCharacter(hStdOut, ' ', 80, coord, NULL);
        // сбрасываем позицию курсора
        SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
    }
    void ptrMoveXCord(bool forward, int distance)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        
        // изменяем позицию курсора
        if(forward == true)
            csbi.dwCursorPosition.X+=distance;
        else
            csbi.dwCursorPosition.X-=distance;
        SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
    }
    int getPtrMaxValue(bool X = true)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);

        if(X = true)
            return csbi.dwCursorPosition.X;
        else
            return csbi.dwCursorPosition.Y;
    }
    void ptrMoveYCord(bool forward, int distance)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        
        // изменяем позицию курсора
        if(forward == true)
            csbi.dwCursorPosition.Y+=distance;
        else
            csbi.dwCursorPosition.Y-=distance;
        SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
    }
    int getCurrentRaw()
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);

        return csbi.dwCursorPosition.Y + 1;
    }
    char getPrevSymbolValue()
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        csbi.dwCursorPosition.X -= 1;
        char prev = 0x00;
        DWORD read = 0;
        ReadConsoleOutputCharacterA(hStdOut, &prev, 1, csbi.dwCursorPosition, &read);
        if(read != 1)
            return -1;
        return prev;
    }
    int getPrevSymbolPos()
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);
        return csbi.dwCursorPosition.X - 1 >= 0 ? csbi.dwCursorPosition.X - 1 : 0;
    }
    std::string getLastSequence(std::string sequence, size_t *orderNumber)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);

        std::string retStr;
        char *symbs = new char[csbi.dwCursorPosition.X + 10];
        memset(symbs, 0, csbi.dwCursorPosition.X + 10);
        DWORD read = 0;

        int sizeToRead = csbi.dwCursorPosition.X;
        csbi.dwCursorPosition.X = 0;
        BOOL bRet = ReadConsoleOutputCharacterA(hStdOut, symbs, sizeToRead, csbi.dwCursorPosition, &read);
        if(read != sizeToRead || bRet != TRUE)
            return retStr;

        std::vector<char*> ptrs;
        char *pTmp = symbs;
        do
        {
            pTmp = strstr(pTmp, sequence.c_str());
            if(pTmp != NULL)
            {
                ptrs.push_back(pTmp);
                pTmp += 1;
            }
        }while(pTmp != NULL);

        if(ptrs.size() > 0)
        {
            retStr.assign(ptrs[ptrs.size() - 1] - 1);

            char* p1 = ptrs[ptrs.size() - 1] - 1, *p2 = &symbs[0];

            *orderNumber = strlen(p1);
        }

        if(symbs != NULL)
            delete[]symbs;

        return retStr;
    }
    bool isFirstSymbolInString(int offset = 0)
    {
        // получаем хэндл окна консоли
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        // получаем данные из буфера вывода консоли
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hStdOut, &csbi);

        if(csbi.dwCursorPosition.X > offset)
            return false;
        else
            return true;
    }
    void putns(const char* ptr)
    {
        for(size_t i = 0; i < strlen(ptr); i ++)
            putchar(ptr[i]);
    }
public:
    ConsoleProcessor()
    {
        prompts.clear();
    }
    std::string processConsoleInput(std::string prePrompt)
    {
        int iFlag = 0;
        char curSymb = 0x00;
        char prevSymb = 0x00;
        std::string str;
        size_t symbolsAfterCommand = 0;
        std::pair<std::string, size_t> limitRule;
        std::string tmpDir;
        FileEnumerator* fen = NULL;
        size_t orderNumber = 0;
        do
        {
            int iSymb = _getch();
            curSymb = iSymb & 0xff;

            if(curSymb == 0x09)
            {
                if(symbolsAfterCommand <= 0)
                {
                    symbolsAfterCommand = 0;

                    if(prompts.size() <= 0)
                        return str;
                    if(iFlag > 0)
                    {
                        clearRow(getCurrentRaw());
                        ptrMoveXCord(false, getPtrMaxValue()/*(int)prompts[iFlag - 1].size() + 1*/);
                        //if(isFirstSymbolInString() == true)
                            printLine(prePrompt, false);
                    }
                    str = prompts[iFlag];
                    putns(prompts[iFlag].c_str());

                    iFlag ++;
                    if(iFlag > (int)prompts.size() - 1)
                        iFlag = 0;
                }
                else /*if(getPrevSymbolValue() == '\\')*/
                {
                    // Обрабатываем автозаполнение вводимого пути

                    bool bChanged = false;
                    std::string tmpString2;

                    tmpString2 = getLastSequence(":\\", &orderNumber);

                    if(prevSymb != curSymb && curSymb == 0x09)
                    {
                        tmpDir.clear();
                        tmpDir = tmpString2;
                        bChanged = true;
                    }
                    else
                        bChanged = false;

                    if(tmpDir.size() > 0)
                    {
                        if(strcmp(limitRule.first.c_str(), tmpDir.c_str()) && bChanged == true)
                        {
                            std::string tmpDir1 = tmpDir;
                            if(fen != NULL)
                                delete fen;
                            if(tmpDir1[tmpDir.size() - 1] != '\\')
                            {
                                size_t sz = 0;
                                for(sz = tmpDir1.size() - 1; sz >= 0; sz --)
                                {
                                    if(tmpDir1.c_str()[sz] == '\\')
                                        break;
                                }

                                tmpDir1.erase(tmpDir1.begin() + sz + 1, tmpDir1.end());
                            }
                            fen = new FileEnumerator(tmpDir1);
                            limitRule.first = tmpDir1;
                            limitRule.second = 0;
                        }
                        // Хватаемся
                        std::string resString;
                        if(tmpDir[tmpDir.size() - 1] == '\\')
                        {
                            // У нас чистый путь без маски
                            std::vector<std::string> res = fen->maskedFiles("");
                            if(res.size() > 0)
                            {
                                if(res.size() >= limitRule.second)
                                    resString = res[limitRule.second ++];
                                if(limitRule.second >= res.size())
                                    limitRule.second = 0;
                            }
                        }
                        else
                        {
                            // Появляется маска
                            size_t sz = 0;
                            for(sz = tmpDir.size() - 1; sz >= 0; sz --)
                                if(tmpDir.c_str()[sz] == '\\')
                                    break;

                            std::string mask = &tmpDir.c_str()[sz + 1];

                            std::vector<std::string> res = fen->maskedFiles(mask);
                            if(res.size() > 0)
                            {
                                if(res.size() >= limitRule.second)
                                    resString = res[limitRule.second ++];
                                if(limitRule.second >= res.size())
                                    limitRule.second = 0;
                            }
                        }
                        if(resString.size() > 0)
                        {
                            std::string tmpString3 = str;
                            tmpString3.erase(tmpString3.end() - orderNumber, tmpString3.end());
                            tmpString3.append(limitRule.first);
                            tmpString3.append(resString);
                            if(tmpString3.size() > str.size())
                                symbolsAfterCommand += tmpString3.size() - str.size();
                            else if(tmpString3.size() < str.size())
                                symbolsAfterCommand += str.size() - tmpString3.size();
                            str = tmpString3;

                            clearRowRight(getCurrentRaw(), orderNumber);
                            std::string newPath = limitRule.first + resString;
                            putns(newPath.c_str());
                        }
                    }
                }
            }
            // Удаляем символ из консоли
            else if(curSymb == 0x08)
            {
                char prev = getPrevSymbolValue();
                if(prev != -1)
                {
                    if(prev == prePrompt.c_str()[0] && getPrevSymbolPos() == 0)
                        ;
                    else
                    {
                        clearCurrentSymbol();
                        str.erase(str.size() - 1);
                        symbolsAfterCommand --;
                    }
                }
            }// Обрабатываем стрелочки
            else if(prevSymb == -32)
            {
                /*if(curSymb == 0x48)
                    ptrMoveYCord(false, 1);
                else if(curSymb == 0x50)
                    ptrMoveYCord(true, 1);
                else */
                if(curSymb == 0x4b)
                {
                    if(isFirstSymbolInString(1) == false)
                        ptrMoveXCord(false, 1);
                }
                else if(curSymb == 0x4D)
                    ptrMoveXCord(true, 1);
            }// Добавляем печатаемый символ в консоли
            else if(curSymb != -32)
            {
                if(curSymb >= ' ' || curSymb < 0x00)
                {
                    str+=curSymb;
                    putchar(curSymb);
                    symbolsAfterCommand++;
                }
            }
            prevSymb = curSymb;
        }while(curSymb != 0x0d);
        putchar(curSymb);
        if(curSymb == 0x0d)
            ptrMoveYCord(true, 1);
        str+=curSymb;

        if(str.size() == 1)
            printLine(prePrompt, false);

        return str;
    }
    void addPrompt(std::string prompt)
    {
        prompts.push_back(prompt);
    }
};

// Компонент для работы пользователя с консолью
class InputProcessor
{
	INetOperator *net, *tcpNet;
    std::string login;
    std::string ip;
    unsigned int port;
    HANDLE hConsoleHandle;
    ConsoleProcessor console;
    static InputProcessor* pSelf;
    std::vector<std::string> blackList;
protected:
    void processLocalCommand(const char* ptr)
    {
        if(strstr(ptr, "help"))
        {
            // Выводим справку по SSL чату
            printSSLChatHelp();
        }
        if(strstr(ptr, "exit") || strstr(ptr, "quit"))
        {
            exit(0);
        }
        if(strstr(ptr, "genkey>"))
        {
            // Генерируем криптоключи
            DataCoder dcr;
            dcr.genKeyComplect(std::string(".//key.tmp"), CKGL_HIGH);
        }
        if(strstr(ptr, "ssert>"))
        {
            // Определяем путь к сертификату
            std::string item;
            item.assign(CodePageManager(std::string(strstr(ptr, "ssert>") + 6), CodePageManager::CPT_OEM).stringValue());
            DataCoder::setSertificatePath(item);
        }
        if(strstr(ptr, "fiwait>"))
        {
            // Управляем обработкой входящих TCP пакетов
            std::string item;
            item.assign(CodePageManager(std::string(strstr(ptr, "fiwait>") + 7), CodePageManager::CPT_OEM).stringValue());
            int i = 0;
            if(item == "enable")
            {
                // Стартуем обработку входящих TCP пакетов
            }
            else if(item == "disable")
            {
                // Останавливаем обработку входящих TCP пакетов
            }
        }
        if(strstr(ptr, "blist>"))
        {
            // Вывести список всех пользователей, занесенных в черный список
            for(size_t sz = 0; sz < blackList.size(); sz ++)
                std::cout << CodePageManager(blackList[sz], CodePageManager::CPT_CHAR).stringValue() << std::endl;
        }
        if(strstr(ptr, "bladd>"))
        {
            // Добавляем пользователя в черный список по его нику
            std::string item;
            item.assign(CodePageManager(std::string(strstr(ptr, "bladd>") + 6), CodePageManager::CPT_OEM).stringValue());
            blackList.push_back(item);
        }
        if(strstr(ptr, "blrem>"))
        {
            // Удаляем пользователя из черного списка по его нику
            std::string item;
            item.assign(CodePageManager(std::string(strstr(ptr, "blrem>") + 6), CodePageManager::CPT_OEM).stringValue());
            for(std::vector<std::string>::iterator it = blackList.begin(); it != blackList.end(); it ++)
            {
                if(strstr(item.c_str(), (*it).c_str()))
                {
                    blackList.erase(it);
                    break;
                }
            }
        }
    }
    void printSSLChatHelp()
    {
        std::string strHelp = "Справка по SSL чату.\r\n\r\n"
            "\r\n"
            "SSL чат позволяет пользователям обмениваться информационными сообщениями в защищенном "
            "режиме. Данная реализация поддерживает работу по протоколу UDP. Возможна работа в "
            "следующих режимах:\r\n"
            "\r\n"
            "1. Вывод информации в общую область видимости. В данном режиме любое информационное "
            "отправленное сообщение будет доставлено всем санкционированным пользователям. Для "
            "отправки сообщения достаточно ввести его в консоли ввода не предваряя никакими "
            "дополнительными конструкциями.\r\n"
            "\r\n"
            "2. Отправка персонального сообщения. В данном режиме пользователь может отправить "
            "сообщение только тому пользователю, который указан в параметрах специализированной "
            "структуры. Структура имеет следующий вид:\r\n"
            "\r\n"
            "<msg:имя конечного пользователя>текст сообщения.\r\n"
            "\r\n"
            "3. Запуск локальной команды. Структура имеет следующий вид: \r\n"
            "\r\n"
            "<cmd:local:имя команды>параметр1,параметр2... \r\n"
            "\r\n"
            "На данный момент реализованы следующие\r\n локальные команды:\r\n"
            "\r\n"
            " - exit осуществляет завершение работы SSL чата.\r\n"
            "\r\n"
            " - help - выводит на экран справку по SSL чату.\r\n"
            "\r\n"
            " - genkey - выполняет генерацию криптографических ключей. \r\n"
            "\r\n"
            " - ssert - выполняет ввод пути к сертификату для ЭЦП. \r\n"
            "\r\n"
            " - blist - выполняет вывод списка пользователей, занесенных в черный список. \r\n"
            "\r\n"
            " - bladd - добавляет пользователя в черный список. В качестве параметра для этой "
            "команды надо указать имя пользователя. \r\n"
            "\r\n"
            " - blrem - добавляет пользователя в черный список. В качестве параметра для этой "
            "команды надо указать имя пользователя. \r\n"
            "\r\n";

        std::cout << "\r\n" << CodePageManager(strHelp, CodePageManager::CPT_CHAR).stringValue() << std::endl;
    }
    void processInputArguments(int argc, char* argv[])
    {
        if(argc >= 4)
        {
            ip.assign(argv[1]);
            port = atoi(argv[2]);
            bool bSpace = false;
            std::string tmpLogin;
            for(int i = 3; i < argc; i ++)
            {
                if(bSpace == true)
                    tmpLogin.append(" ");
                tmpLogin.append(argv[i]);
                bSpace = true;
            }
            login.assign(CodePageManager(tmpLogin, CodePageManager::CPT_CHAR).stringValue());
        }
        else
        {
            printLine("Введите Ваш логин: ", false);
            std::string tmpLogin;
            std::getline(std::cin, tmpLogin);
            login.assign(CodePageManager(tmpLogin, CodePageManager::CPT_OEM).stringValue());
            if(login.size() <= 0)
                login = DEFAULT_USER;


            printLine("\r\nВведите IP адрес сети: ", false);
            std::cin >> ip;

            if(ip.size() <= 0 || inet_addr(ip.c_str()) == INADDR_NONE)
                ip = DEFAULT_IP;
        }
    }
    
public:
	InputProcessor(int argc, char* argv[])
        : net(NULL), port(DEFAULT_PORT)
	{
        blackList.clear();

        // Задаем все применяемые в программе варианты автозаполнения
        console.addPrompt("<msg:");
        console.addPrompt("<cmd:local:help>");
        console.addPrompt("<cmd:local:ssert>");
        console.addPrompt("<cmd:local:fiwait>");
        console.addPrompt("<cmd:local:genkey>");
        console.addPrompt("<cmd:local:blist>");
        console.addPrompt("<cmd:local:exit>");
        console.addPrompt("<cmd:local:bladd>");
        console.addPrompt("<cmd:local:blrem>");
        console.addPrompt("");

        SetConsoleCP(866);
        SetConsoleOutputCP(866);

        processInputArguments(argc, argv);

        pSelf = this;

        net = new NetOperatorUDP(&InputProcessor::printIncomingMessage, port);

		assert(net != NULL);

		std::string inStr;

        std::string tmp = "пользователь ";
        tmp += login;
        tmp += " активирован.\r\n\r\nСообщения:\r\n";

        net->waitForInputPacket();

        printLine(tmp);

        bool bHead = true;

        while(std::cin.good())
		{
            std::cout.flush();
            std::string tmp = "$";

            if(bHead == true)
            {
                bHead = false;
                printLine(tmp, false);
            }

            // Ожидаем выбора горячей комбинации при помощи табулятора
            std::string str = console.processConsoleInput(tmp);

            std::string tmpInStr;

            if(str.c_str()[str.size() - 1] != 0x0d)
                std::getline(std::cin, tmpInStr);
            else
                str.erase(str.size() - 1);

            inStr.clear();

            inStr.append(str);
            inStr.append(tmpInStr);

            if(strstr(inStr.c_str(), "<cmd:local:") != NULL)
            {
                // Обрабатываем локальную команду

                processLocalCommand(inStr.c_str() + 11);
            }
            if(inStr == "help")
            {
                printSSLChatHelp();
            }
            else if((inStr != "exit") && (inStr != "quit"))
            {
                if(inStr.size() > 0)
                {
                    if(CodePageManager(inStr, CodePageManager::CPT_OEM).stringValue() == "выход")
                        return;

                    net->sendOutputPacket(ip, 
                        ChatAtomPacket(login + 
                        ": " + 
                        CodePageManager(inStr, CodePageManager::CPT_OEM).stringValue()));

                    Sleep(20);

                    if(inStr.size() == 0)
                        bHead = false;
                    else
                        bHead = true;
                }
            }
            else
                break;
		}
	}
	virtual ~InputProcessor()
	{
		if(net != NULL)
			delete net;

        blackList.clear();
	}
    static void printIncomingMessage(ChatAtomPacket &cap)
    {
        if(cap.getCurrentData() == "-1" || cap.getCurrentData().size() <= 0)
            return;

        int iCtr = 0;
        std::string tmpLogin;
        while(cap.getCurrentData().c_str()[iCtr] != ':')
            tmpLogin += cap.getCurrentData().c_str()[iCtr ++];

        if(strstr(tmpLogin.c_str(), pSelf->login.c_str()))
            return;

        // Тут можно вставить дополнительную проверку на входящие сообщения будь то 
        // удаленные команды 
        // или 
        // персональные сообщения
        WORD wColor = FOREGROUND_GREEN;

        bool bPersonal = false;

        if(strstr(cap.getCurrentData().c_str(), "cmd"))
            wColor = FOREGROUND_RED;
        else if(strstr(cap.getCurrentData().c_str(), "msg"))
        {
            if(strstr(cap.getCurrentData().c_str(), pSelf->login.c_str()) == NULL)
                return;
            else
                bPersonal = true;
            wColor = FOREGROUND_BLUE;
        }
        else
            wColor = FOREGROUND_GREEN;

        // Проверка пользователя на принадлежность его черному списку
        for(size_t sz = 0; sz < pSelf->blackList.size(); sz ++)
            if(strstr(tmpLogin.c_str(), pSelf->blackList[sz].c_str()))
                return;

        // Выводим принятые данные в консоль
        std::string inComing;

        if(bPersonal == false)
            inComing = cap.getCurrentData();
        else
        {
            // Если сообщение было отправлено персонально 
            // его необходимо извлечь из вспомогательной структуры
            std::string tmpStr = cap.getCurrentData();
            char *tmp = new char[tmpStr.size() + 1];

            assert(tmp);

            memset(tmp, 0, tmpStr.size() + 1);
            for(size_t sz = 0; sz < tmpStr.size(); sz ++)
                tmp[sz] = tmpStr.c_str()[sz];
            char *pLogin = tmp, *pBody = NULL, *pBase = tmp;

            size_t ctr = 0;
            while(*++tmp != ' ')
            {
                if(++ctr >= tmpStr.size())
                {
                    if(pBase != NULL)
                        delete[] pBase;
                    return;
                }
            }
            *tmp++ = 0x00;
            pBody = strstr(tmp, pSelf->login.c_str());

            if(pBody == NULL)
            {
                if(pBase != NULL)
                    delete[] pBase;
                return;
            }
            pBody += pSelf->login.size() + 1;
            inComing.append(pLogin);
            inComing.append(" ");
            inComing.append(pBody, strlen(pBody) - 1);
            if(pBase != NULL)
                delete[] pBase;
        }

        inComing += "\r\n";
            
        CONSOLE_SCREEN_BUFFER_INFO *consoleInfo = new CONSOLE_SCREEN_BUFFER_INFO();

        assert(consoleInfo != NULL);

        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo);
        WORD OriginalColors = consoleInfo->wAttributes;

        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wColor);
        printLine(inComing, false);
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), OriginalColors);

        printLine("$", false);

        if(consoleInfo != NULL)
            delete consoleInfo;
    }
};
InputProcessor* InputProcessor::pSelf = NULL;

class TestRandomizer
{
    FILE* fp;
    BYTE* getRandomBytes(BYTE* buf, size_t buflen, BYTE iv, BYTE module = 0xff)
    {
        if(buf == NULL)
            return NULL;
        memset(buf, 0, buflen*sizeof(BYTE));
        DWORD rbase = GetTickCount();
        buf[0] = (iv ^ (BYTE)((rbase >> 8) & 0xff)) % module;
        for(size_t sz = 1; sz < buflen; sz ++)
            buf[sz] = (buf[sz - 1] ^ (BYTE)((rbase >> (sz % 8)) & 0xff)) % module;
        return buf;
    }
    void simpleTest(BYTE iv)
    {
        BYTE buf[10];
        int ctr = 0;
        while(ctr++<10)
            getRandomBytes(buf, sizeof(buf), iv, 25);
    }
    std::string bin2string(BYTE* data, int size)
    {
        std::string str;
        for(int i = 0; i < size; i ++)
        {
            for(int j = 0; j < 2; j ++)
            {
                char curNibble = (((char)data[i] >> 4*(1 - j)) & 0xf);
                if(curNibble >= 0 && curNibble <= 9)
                    curNibble += 0x30;
                else
                    curNibble += 0x37;
                str += curNibble;
            }
        }
        return str;
    }
    void test(BYTE iv)
    {
        fflush(fp);

        for(int i = 0; i < 1000; i ++)
        {
            //Sleep(20);
            BYTE buf[10] = {0};
            getRandomBytes(buf, sizeof(buf), iv, 25);
            std::string str = bin2string(buf, sizeof(buf));
            str += "\r\n";
            fwrite(str.c_str(), str.size(), 1, fp);
        }
    }
public:
    TestRandomizer(BYTE iv)
        : fp(NULL)
    {
        fopen_s(&fp, "rbtest.txt", "a+t");

        test(iv);
    }
    ~TestRandomizer()
    {
        if(fp != NULL)
            fclose(fp);
    }
};

void main(int argc, char* argv[])
{
    //TestRandomizer tr_(0x18);
	InputProcessor ip_(argc, argv);
}