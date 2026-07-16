// ==================== 版本和编译宏 ====================
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <ws2tcpip.h>
#include <easyx.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <deque>
#include <algorithm>
#include <ctime>
#include <cstdio>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ---------- 界面尺寸 ----------
const int WIN_W = 1100;
const int WIN_H = 700;
const int MAX_POINTS = 60;        // 显示最近60秒

// ---------- 速度统计 ----------
struct SpeedData {
    std::deque<int> inData;
    std::deque<int> outData;
    int maxVal = 10;              // Y轴当前最大值（平滑后）
};
SpeedData g_speed;

// ---------- 数据包日志 ----------
struct PacketLog {
    std::string time;
    std::string src;
    std::string dst;
    std::string protocol;
    int len;
};
std::deque<PacketLog> g_logs;

// ---------- 本机 IP ----------
std::vector<ULONG> g_localIPs;

// ---------- 抓包句柄 ----------
pcap_t* g_adhandle = nullptr;
bool g_capturing = false;

// ---------- 平滑 Catmull-Rom 插值 ----------
void CatmullRomToPoints(const std::deque<int>& data, int graphX, int graphY, int graphW, int graphH,
    std::vector<POINT>& outPoints) {
    if (data.size() < 2) {
        outPoints.clear();
        return;
    }

    int n = (int)data.size();
    std::vector<POINT> pts(n);
    for (int i = 0; i < n; i++) {
        int x = graphX + (int)((i + (MAX_POINTS - n)) * (double)graphW / MAX_POINTS);
        int y = graphY + graphH - (int)(data[i] * (double)graphH / (double)(g_speed.maxVal + 1));
        pts[i] = { x, y };
    }

    outPoints.clear();
    outPoints.reserve((n - 1) * 4 + 1);

    auto getP = [&](int idx) -> POINT {
        if (idx < 0) return pts[0];
        if (idx >= n) return pts[n - 1];
        return pts[idx];
        };

    for (int i = 0; i < n - 1; i++) {
        POINT p0 = getP(i - 1);
        POINT p1 = pts[i];
        POINT p2 = pts[i + 1];
        POINT p3 = getP(i + 2);

        for (int t = 0; t < 4; t++) {
            double s = t / 3.0;
            double s2 = s * s;
            double s3 = s2 * s;

            double x = 0.5 * ((2 * p1.x) + (-p0.x + p2.x) * s + (2 * p0.x - 5 * p1.x + 4 * p2.x - p3.x) * s2 + (-p0.x + 3 * p1.x - 3 * p2.x + p3.x) * s3);
            double y = 0.5 * ((2 * p1.y) + (-p0.y + p2.y) * s + (2 * p0.y - 5 * p1.y + 4 * p2.y - p3.y) * s2 + (-p0.y + 3 * p1.y - 3 * p2.y + p3.y) * s3);
            outPoints.push_back({ (int)x, (int)y });
        }
    }
    outPoints.push_back(pts[n - 1]);
}

// ---------- 获取本机 IPv4 ----------
void GetLocalIPs() {
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->IpAddressList.IpAddress.String[0] != '0') {
                ULONG ip = 0;
                if (inet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &ip) == 1) {
                    g_localIPs.push_back(ip);
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
}

// ---------- 判断方向 ----------
bool IsInbound(ULONG srcIP, ULONG dstIP) {
    for (ULONG ip : g_localIPs) if (dstIP == ip) return true;
    return false;
}

// ---------- 协议名 ----------
std::string GetProtocol(int ipProtocol) {
    switch (ipProtocol) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    default: return "IP_" + std::to_string(ipProtocol);
    }
}

// ---------- 时间字符串 ----------
std::string GetTimeStr() {
    time_t now = time(nullptr);
    tm tm;
    localtime_s(&tm, &now);
    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
    return std::string(buf);
}

// ---------- 抓包线程 ----------
DWORD WINAPI CaptureThread(LPVOID) {
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;
    pcap_setnonblock(g_adhandle, 1, nullptr);

    while (g_capturing) {
        res = pcap_next_ex(g_adhandle, &header, &pkt_data);
        if (res == 0) { Sleep(1); continue; }
        if (res < 0) break;

        const u_char* ip_header = pkt_data + 14;
        int ip_version = (ip_header[0] >> 4) & 0x0F;
        if (ip_version != 4) continue;

        int ip_header_len = (ip_header[0] & 0x0F) * 4;
        ULONG srcIP = *(ULONG*)(ip_header + 12);
        ULONG dstIP = *(ULONG*)(ip_header + 16);
        u_char protocol = ip_header[9];

        const u_char* transport_header = ip_header + ip_header_len;
        int srcPort = 0, dstPort = 0;
        if (protocol == 6 || protocol == 17) {
            srcPort = (transport_header[0] << 8) | transport_header[1];
            dstPort = (transport_header[2] << 8) | transport_header[3];
        }

        bool inbound = IsInbound(srcIP, dstIP);
        int packetSizeKB = (header->len + 1023) / 1024;

        if (inbound) {
            if (!g_speed.inData.empty()) g_speed.inData.back() += packetSizeKB;
        }
        else {
            if (!g_speed.outData.empty()) g_speed.outData.back() += packetSizeKB;
        }

        static int log_counter = 0;
        if (++log_counter % 5 == 0) {
            PacketLog log;
            log.time = GetTimeStr();
            char buf[64];
            sprintf(buf, "%u.%u.%u.%u", (srcIP >> 0) & 0xFF, (srcIP >> 8) & 0xFF, (srcIP >> 16) & 0xFF, (srcIP >> 24) & 0xFF);
            log.src = buf;
            sprintf(buf, "%u.%u.%u.%u", (dstIP >> 0) & 0xFF, (dstIP >> 8) & 0xFF, (dstIP >> 16) & 0xFF, (dstIP >> 24) & 0xFF);
            log.dst = buf;
            log.protocol = GetProtocol(protocol);
            if (srcPort && dstPort) {
                log.protocol += ":" + std::to_string(srcPort) + "->" + std::to_string(dstPort);
            }
            log.len = header->len;
            g_logs.push_front(log);
            if ((int)g_logs.size() > 50) g_logs.pop_back();
        }
    }
    return 0;
}

// ---------- 绘图（双缓冲 + 右侧遮罩 + Y轴平滑） ----------
void DrawUI(IMAGE* pBuf) {
    SetWorkingImage(pBuf);
    cleardevice();

    // 标题
    settextstyle(20, 0, _T("微软雅黑"));
    settextcolor(RGB(200, 200, 200));
    outtextxy(10, 10, _T("📡 本地网络分析器 — 平滑曲线 + 列表视图"));

    // ===== 曲线图区域 =====
    int graphX = 50, graphY = 60, graphW = 1000, graphH = 280;
    rectangle(graphX, graphY, graphX + graphW, graphY + graphH);
    settextcolor(WHITE);
    outtextxy(graphX + 10, graphY - 25, _T("流量曲线 (KB/s) — 入站(红)  出站(蓝)"));

    // 网格和Y轴标签
    setlinestyle(PS_DASH, 1);
    setlinecolor(RGB(60, 60, 60));
    for (int y = 0; y <= 4; y++) {
        int yy = graphY + graphH - (y * graphH / 4);
        line(graphX, yy, graphX + graphW, yy);
        wchar_t buf[32];
        swprintf(buf, 32, L"%d KB", (g_speed.maxVal / 4) * y);
        outtextxy(graphX - 50, yy - 8, buf);
    }

    // 绘制平滑曲线
    if (g_speed.inData.size() > 1) {
        std::vector<POINT> inPts, outPts;
        CatmullRomToPoints(g_speed.inData, graphX, graphY, graphW, graphH, inPts);
        CatmullRomToPoints(g_speed.outData, graphX, graphY, graphW, graphH, outPts);

        setlinestyle(PS_SOLID, 3);
        if (!inPts.empty()) {
            setlinecolor(RED);
            polyline(inPts.data(), (int)inPts.size());
        }
        if (!outPts.empty()) {
            setlinecolor(BLUE);
            polyline(outPts.data(), (int)outPts.size());
        }
    }

    // ---------- 关键改动：右侧遮罩，覆盖曲线末端 ----------
    // 用背景色矩形覆盖图形区域最右侧 12 像素，让曲线“消失”在边缘
    setfillcolor(RGB(30, 30, 35));   // 与背景色一致
    solidrectangle(graphX + graphW - 12, graphY, graphX + graphW, graphY + graphH);
    // 重新画边框（确保遮罩不破坏边框）
    setlinecolor(RGB(255, 255, 255));
    rectangle(graphX, graphY, graphX + graphW, graphY + graphH);

    // ===== 实时数值 =====
    int inRate = g_speed.inData.empty() ? 0 : g_speed.inData.back();
    int outRate = g_speed.outData.empty() ? 0 : g_speed.outData.back();
    wchar_t statBuf[256];
    swprintf(statBuf, 256, L"当前入站: %d KB/s    当前出站: %d KB/s    峰值: %d KB/s", inRate, outRate, g_speed.maxVal);
    settextcolor(RGB(180, 255, 180));
    outtextxy(50, 360, statBuf);

    // ===== 数据包列表 =====
    int listX = 50, listY = 400, listW = 1000, listH = 260;
    setfillcolor(RGB(50, 50, 60));
    solidrectangle(listX, listY, listX + listW, listY + 30);
    settextcolor(RGB(220, 220, 255));
    outtextxy(listX + 10, listY + 6, _T("时间"));
    outtextxy(listX + 100, listY + 6, _T("源 IP"));
    outtextxy(listX + 300, listY + 6, _T("目的 IP"));
    outtextxy(listX + 500, listY + 6, _T("协议"));
    outtextxy(listX + 700, listY + 6, _T("长度 (B)"));
    setlinecolor(RGB(100, 100, 120));
    line(listX, listY + 30, listX + listW, listY + 30);

    int rowHeight = 20;
    int maxRows = (listH - 30) / rowHeight;
    int total = (int)g_logs.size();
    int startIdx = (total > maxRows) ? total - maxRows : 0;

    settextstyle(16, 0, _T("Consolas"));
    for (int i = startIdx; i < total; i++) {
        const auto& log = g_logs[i];
        int yPos = listY + 30 + (i - startIdx) * rowHeight;
        if ((i - startIdx) % 2 == 0) {
            setfillcolor(RGB(35, 35, 40));
            solidrectangle(listX, yPos, listX + listW, yPos + rowHeight);
        }
        line(listX, yPos + rowHeight, listX + listW, yPos + rowHeight);
        wchar_t lineBuf[512];
        swprintf(lineBuf, 512, L"%hs  %hs  %hs  %hs  %d",
            log.time.c_str(), log.src.c_str(), log.dst.c_str(),
            log.protocol.c_str(), log.len);
        settextcolor(RGB(200, 200, 200));
        outtextxy(listX + 10, yPos + 2, lineBuf);
    }
    rectangle(listX, listY, listX + listW, listY + listH);

    // 将内存画布内容拷贝到屏幕
    SetWorkingImage(nullptr);
    putimage(0, 0, pBuf);
}

// ---------- 主函数 ----------
int main() {
    // 初始化 Npcap
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        MessageBoxA(nullptr, "未找到网卡或Npcap未安装！请以管理员身份运行。", "错误", MB_OK);
        return 1;
    }
    pcap_if_t* dev = alldevs;
    while (dev) {
        if (dev->addresses && dev->addresses->addr) break;
        dev = dev->next;
    }
    if (!dev) {
        pcap_freealldevs(alldevs);
        MessageBoxA(nullptr, "没有找到有效的网卡设备。", "错误", MB_OK);
        return 1;
    }

    g_adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);
    if (!g_adhandle) {
        MessageBoxA(nullptr, "打开网卡失败，请以管理员权限运行。", "错误", MB_OK);
        return 1;
    }

    struct bpf_program fcode;
    if (pcap_compile(g_adhandle, &fcode, "ip", 1, 0xFFFFFF) >= 0) {
        pcap_setfilter(g_adhandle, &fcode);
    }

    GetLocalIPs();
    if (g_localIPs.empty()) {
        MessageBoxA(nullptr, "无法获取本机IP，请检查网络。", "警告", MB_OK);
    }

    initgraph(WIN_W, WIN_H);
    setbkcolor(RGB(30, 30, 35));

    IMAGE buffer(WIN_W, WIN_H);
    SetWorkingImage(&buffer);
    cleardevice();
    SetWorkingImage(nullptr);

    g_capturing = true;
    HANDLE hThread = CreateThread(nullptr, 0, CaptureThread, nullptr, 0, nullptr);

    while (!GetAsyncKeyState(VK_ESCAPE)) {
        static int tick = 0;
        if (++tick % 10 == 0) {
            g_speed.inData.push_back(0);
            g_speed.outData.push_back(0);
            if ((int)g_speed.inData.size() > MAX_POINTS) {
                g_speed.inData.pop_front();
                g_speed.outData.pop_front();
            }

            // 平滑自适应 Y 轴
            int rawMax = 1;
            for (int v : g_speed.inData) if (v > rawMax) rawMax = v;
            for (int v : g_speed.outData) if (v > rawMax) rawMax = v;
            int targetMax = ((rawMax / 10) + 1) * 10;
            if (targetMax < 10) targetMax = 10;
            if (targetMax > g_speed.maxVal) {
                g_speed.maxVal = targetMax;
            }
            else if (targetMax < g_speed.maxVal) {
                int delta = (g_speed.maxVal - targetMax) / 8;  // 缓慢下降
                if (delta < 1) delta = 1;
                g_speed.maxVal -= delta;
                if (g_speed.maxVal < targetMax) g_speed.maxVal = targetMax;
            }
        }

        DrawUI(&buffer);
        Sleep(50);
    }

    g_capturing = false;
    WaitForSingleObject(hThread, 3000);
    if (g_adhandle) pcap_close(g_adhandle);
    closegraph();
    return 0;
}