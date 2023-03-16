#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>

#include "qdebug.h"
#include <QThread>
#include <stdlib.h>
#include <stdio.h>
#include <QProcess>
#include <QStringList>
#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <QNetworkDatagram>
#include <QSslSocket>
#define MAX_PRINT 80
#define MAX_LINE 16
#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
    TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

quint16 readLength(QByteArray& data, uint pos) {
    quint16 length = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos+1];
    return length;
}

int printServerName(const struct pcap_pkthdr* pkthdr, const u_char* data)
{
    QByteArray packetData((char*) data, pkthdr->len);
    packetData = packetData.mid(42);
//    qDebug() <<packetData.size() << " " << (int)packetData.at(12) << " " << data[54];
    if (packetData.size() > 13 && packetData.at(12) == 22) {

        // Check if the TLS handshake contains a Server Name extension
        QByteArray tlsData = packetData.mid(17);
        if (tlsData.size() > 42 && (tlsData.at(0) == 1 || tlsData.at(0) == 2)) {
            //qDebug() << "Client Hello " << (int) tlsData[2] << " " << (int) tlsData[3];
            //qDebug() << "Handshake Length " << readLength(tlsData, 2);
            quint16 sessionLength = (quint16) tlsData[38];
            //qDebug() << "session Length " << sessionLength;
            quint16 cipherLength = readLength(tlsData, 39 + sessionLength);
            //qDebug() << "cipher Length " << cipherLength;
            quint16 compressionLength = (quint16) tlsData[41 + sessionLength + cipherLength];
            //qDebug() << "compressionLength " << compressionLength ;
            int extensionsLengthIndex = 41 + sessionLength + cipherLength + 1 + compressionLength;
            quint16 extensionsLength = readLength(tlsData, extensionsLengthIndex);
            //qDebug() << "ExtensionsLength " << extensionsLength;
            QByteArray extensionsData = tlsData.mid(extensionsLengthIndex + 2, extensionsLength);
            while (extensionsData.size() > 0) {
                quint16 extensionType = ((unsigned char)extensionsData[0] << 8) | (unsigned char)extensionsData[1];
                quint16 extensionLength = ((unsigned char)extensionsData[2] << 8) | (unsigned char)extensionsData[3];
                //qDebug() << "Extension Type " << extensionType << " " << extensionLength;
                if (extensionType == 0) {
                    // This is the Server Name extension
                    QByteArray serverNameData = extensionsData.mid(4, extensionLength);
                    quint16 serverNameListLength = ((unsigned char)serverNameData[0] << 8) | (unsigned char)serverNameData[1];

                   // qDebug() << "server name list length " << serverNameListLength << " " << (int) serverNameData[0] << (int) serverNameData[1];
                    //qDebug() << "server name type" << (uint)serverNameData[2];
                    quint16 serverNameLength = ((unsigned char)serverNameData[3] << 8) | (unsigned char)serverNameData[4];
                    //qDebug() << "server name length" << serverNameLength;
//                    QString serverName = QString::fromUtf8(serverNameData.mid(5, serverNameData.length() - 5));
                    //qDebug() << "Server Name: " << serverNameData.toHex();
                    qDebug() << "Server Name: " << serverNameData.mid(5);
                    return 1;

                }
                extensionsData = extensionsData.mid(extensionLength + 4);
            }
        }
    }
    return 0;
}
QString getProcessNameFromPort(quint16 port)
{
    QString processName;
    MIB_TCPTABLE_OWNER_PID* tcpTable = NULL;
    ULONG tcpTableSize = 0;
    DWORD result = GetExtendedTcpTable(tcpTable, &tcpTableSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (MIB_TCPTABLE_OWNER_PID*) malloc(tcpTableSize);
        if (tcpTable != NULL) {
            result = GetExtendedTcpTable(tcpTable, &tcpTableSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result == NO_ERROR) {
                for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
                    if (row.dwLocalPort == htons(port)) {
                        HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                        if (processSnapshot != INVALID_HANDLE_VALUE) {
                            PROCESSENTRY32 processEntry = {0};
                            processEntry.dwSize = sizeof(PROCESSENTRY32);
                            if (Process32First(processSnapshot, &processEntry)) {
                                do {
                                    if (processEntry.th32ProcessID == row.dwOwningPid) {
                                        processName = QString::fromWCharArray(processEntry.szExeFile);
                                        break;
                                    }
                                } while (Process32Next(processSnapshot, &processEntry));
                            }
                            CloseHandle(processSnapshot);
                        }
                        break;
                    }
                }
            }
            free(tcpTable);
        }
    }
    return processName;
}

void print_interface_names()
{
    pcap_if_t *interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get a list of all network interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        qCritical() << "Error finding network interfaces:" << errbuf;
        return;
    }

    // Print the names of all network interfaces
    pcap_if_t *iface;
    for (iface = interfaces; iface != NULL; iface = iface->next) {
        qDebug() << "Interface name:" << iface->name << " " << iface->description;
    }

    // Free the list of network interfaces
    pcap_freealldevs(interfaces);
}


class PacketCaptureThread: public QThread{
public:
    void run() override
    {
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        char *source = NULL;
        char *ofilename = NULL;
        char *filter = NULL;

        int i;
        pcap_dumper_t *dumpfile;
        struct bpf_program fcode;
        bpf_u_int32 NetMask;
        int res;
        struct pcap_pkthdr *header;
        const u_char* pkt_data;
        #ifdef _WIN32
            /* Load Npcap and its functions. */
            if (!LoadNpcapDlls())
            {
                fprintf(stderr, "Couldn't load Npcap\n");
                exit(1);
            }
        #endif
        source = "\\Device\\NPF_{AAFA6A99-2686-40CB-AA91-EDD149301E12}";
        ofilename = "out.out";
        filter = "tcp dst port 443";
        if((fp = pcap_open(source, -1, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL){
            fprintf(stderr, "\nUnable to open the adapter:%s\n", errbuf);
            return;
        }
        NetMask = 0xffffff;
        if((res = pcap_compile(fp, &fcode, filter, 1, NetMask))<0){
            fprintf(stderr,"\nError compiling filter: %s\n", pcap_statustostr(res));
            pcap_close(fp);
            return;
        }
        if((res = pcap_setfilter(fp, &fcode))<0)
        {
            fprintf(stderr,"\nError setting the filter: %s\n", pcap_statustostr(res));
            pcap_close(fp);
            return;
        }
        dumpfile= pcap_dump_open(fp, ofilename);

        if (dumpfile == NULL)
        {
           fprintf(stderr,"\nError opening output file: %s\n", pcap_geterr(fp));
           pcap_close(fp);
           return;
        }
        while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
        {
            //qDebug() << res;
            if(res == 0)
            /* Timeout elapsed */
            continue;
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            snprintf(src_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]);
            snprintf(dst_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]);
            //save the packet on the dump file

            uint16_t src_port = (pkt_data[34] << 8) | pkt_data[35];
            uint16_t dst_port = (pkt_data[36] << 8) | pkt_data[37];
            QString srcProcess = getProcessNameFromPort(src_port);
            QString dstProcess = getProcessNameFromPort(dst_port);
//            if(header->len > 300) {
                //qDebug() << header->len << " " << srcProcess;

//            }
//            else continue;
            if(!printServerName(header, pkt_data)) continue;
            if(srcProcess==""&&dstProcess == "" && (src_port == 80 || dst_port == 80)) srcProcess = "chrome.exe";
            if(srcProcess == "chrome.exe" || dstProcess == "chrome.exe" ) {
                //printServerName(header, pkt_data);

                qDebug() << "Source IP: " << src_ip << " Source port: " << src_port;

                qDebug() << "Destination IP: " << dst_ip << "Destination port: " << dst_port;
                if(srcProcess != "") qDebug() << "process:" << srcProcess;
                else if(dstProcess != "") qDebug() << "process:" << dstProcess;
                qDebug() << "----------------------------";
            }

            pcap_dump((unsigned char *) dumpfile, header, pkt_data);


        }
    }

};



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    //print_interface_names();

    qDebug() << "----------------------------";
    PacketCaptureThread* thread = new PacketCaptureThread();
    thread -> start();

}


MainWindow::~MainWindow()
{
    delete ui;

}

