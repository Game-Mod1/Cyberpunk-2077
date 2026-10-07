#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_BTN_ATTACH       1001
#define ID_CHK_HEALTH       1002
#define ID_CHK_STAMINA      1003
#define ID_CHK_RAM          1004
#define ID_CHK_AMMO         1005
#define ID_CHK_RELOAD       1006
#define ID_CHK_RECOIL       1007
#define ID_CHK_ACCURACY     1008
#define ID_CHK_ITEMS        1009
#define ID_CHK_XP           1010
#define ID_CHK_STREETXP     1011
#define ID_CHK_STEALTH      1012
#define ID_CHK_FLY          1013
#define ID_CHK_DOUBLEJUMP   1014
#define ID_CHK_SUPERJUMP    1015
#define ID_CHK_HACKTIME     1016
#define ID_CHK_DAYTIME      1017
#define ID_EDIT_SPEED       1018
#define ID_BTN_SPEED        1019
#define ID_EDIT_MONEY       1020
#define ID_BTN_MONEY        1021
#define ID_STATUS           1022
#define ID_TIMER            2001

HWND g_hwnd = NULL;
HWND g_hStatus = NULL;
HANDLE g_hProcess = NULL;
DWORD g_dwPID = 0;
uintptr_t g_modBase = 0;
size_t g_modSize = 0;

bool g_health = false, g_stamina = false, g_ram = false, g_ammo = false;
bool g_reload = false, g_recoil = false, g_accuracy = false, g_items = false;
bool g_xp = false, g_streetxp = false, g_stealth = false, g_fly = false;
bool g_doublejump = false, g_superjump = false, g_hacktime = false, g_daytime = false;

uintptr_t addr_health = 0, addr_stamina = 0, addr_reload = 0, addr_recoil = 0;
uintptr_t addr_accuracy = 0, addr_items = 0, addr_stealth = 0, addr_fly = 0;
uintptr_t addr_doublejump = 0, addr_superjump = 0, addr_hacktime = 0, addr_daytime = 0;
uintptr_t addr_setstats = 0, addr_player = 0, addr_inventory = 0, addr_stats = 0;

BYTE pat_health[] = {0x8A,0x87,0xAE,0x01,0x00,0x00,0x88};
char  msk_health[] = "xxxxxxx";
BYTE pat_stamina[] = {0xF3,0x0F,0x10,0x89,0x00,0x00,0x00,0x00,0x0F,0x28,0xD6};
char  msk_stamina[] = "xxxx????xxx";
BYTE pat_reload[] = {0x66,0x2B,0xC6,0x0F,0xB7,0x00,0x39,0x00,0x00,0x74};
char  msk_reload[] = "xxxxx?x??x";
BYTE pat_recoil[] = {0x74,0x00,0x00,0x8B,0x00,0x00,0x8D};
char  msk_recoil[] = "x??x??x";
BYTE pat_accuracy[] = {0xF3,0x0F,0x11,0x89,0x00,0x00,0x00,0x00,0x00,0x8B};
char  msk_accuracy[] = "xxxx????x?";
BYTE pat_items[] = {0xE8,0x00,0x00,0x00,0x00,0x84,0xC0,0x74};
char  msk_items[] = "x????xxx";
BYTE pat_stealth[] = {0x41,0x38,0x76,0x08,0x0F,0x84};
char  msk_stealth[] = "xxxxxx";
BYTE pat_fly[] = {0xF2,0x0F,0x11,0x8E,0x00,0x00,0x00,0x00,0x00,0x85};
char  msk_fly[] = "xxxx????x?";
BYTE pat_doublejump[] = {0x48,0x8B,0x48,0x08,0x49,0x3B,0xC8,0x74};
char  msk_doublejump[] = "xxxxxxxx";
BYTE pat_superjump[] = {0xF3,0x45,0x0F,0x59,0xC2,0xF3,0x44,0x0F,0x11,0x83};
char  msk_superjump[] = "xxxxxxxxxx";
BYTE pat_hacktime[] = {0xF3,0x0F,0x5C,0x00,0x0F,0x2F,0x00,0xF3,0x0F,0x11};
char  msk_hacktime[] = "xxxxxx?xxx";
BYTE pat_daytime[] = {0xF3,0x48,0x0F,0x2C,0xF8,0x48,0x8B,0x01,0x8B,0xD7};
char  msk_daytime[] = "xxxxxxxxxx";
BYTE pat_setstats[] = {0xF3,0x41,0x0F,0x11,0x82,0x00,0x00,0x00,0x00,0x0F,0x84};
char  msk_setstats[] = "xxxxx????xx";
BYTE pat_player[] = {0x41,0xB8,0x11,0x00,0x00,0x00,0x48,0x8B,0x01};
char  msk_player[] = "xxxxxxxxx";
BYTE pat_inventory[] = {0x48,0x8B,0x48,0x10,0x48,0x85,0xFF,0x74};
char  msk_inventory[] = "xxxxxxxx";
BYTE pat_stats[] = {0x48,0x8B,0x0E,0x4C,0x8B,0xC0};
char  msk_stats[] = "xxxxxx";

bool MatchPattern(const BYTE* data, const BYTE* pat, const char* mask, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (mask[i] == 'x' && data[i] != pat[i]) return false;
    }
    return true;
}

uintptr_t PatternScan(HANDLE hProc, uintptr_t start, size_t size, const BYTE* pat, const char* mask) {
    size_t plen = strlen(mask);
    const size_t CHUNK = 0x10000;
    std::vector<BYTE> buf(CHUNK + plen);
    for (size_t offset = 0; offset < size; offset += CHUNK) {
        size_t toRead = (std::min)(CHUNK + plen, size - offset);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(start + offset), buf.data(), toRead, &bytesRead) || bytesRead < plen)
            continue;
        for (size_t i = 0; i + plen <= bytesRead; i++) {
            if (MatchPattern(buf.data() + i, pat, mask, plen))
                return start + offset + i;
        }
    }
    return 0;
}

DWORD FindProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName, size_t* outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me = {sizeof(me)};
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                if (outSize) *outSize = me.modBaseSize;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

bool WriteBytes(uintptr_t addr, const BYTE* data, size_t len) {
    if (!g_hProcess || !addr) return false;
    DWORD old;
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, PAGE_EXECUTE_READWRITE, &old);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(g_hProcess, (LPVOID)addr, data, len, &written);
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, old, &old);
    return ok && written == len;
}

bool NopBytes(uintptr_t addr, size_t len) {
    std::vector<BYTE> nops(len, 0x90);
    return WriteBytes(addr, nops.data(), len);
}

bool WriteMem(uintptr_t addr, const void* buf, size_t len) {
    return WriteBytes(addr, (const BYTE*)buf, len);
}

void SetStatus(const wchar_t* msg) {
    if (g_hStatus) SetWindowTextW(g_hStatus, msg);
}

void ApplyHealth(bool on) {
    if (!addr_health) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_health + 0x06, patch, 6);
    }
}

void ApplyStamina(bool on) {
    if (!addr_stamina) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_stamina, patch, 8);
    }
}

void ApplyRAM(bool on) {
    if (!addr_stamina) return;
    if (on) {
        float zero = 0.0f;
        WriteMem(addr_stamina + 0x0C, &zero, 4);
    }
}

void ApplyAmmo(bool on) {
    if (!addr_reload) return;
    if (on) {
        BYTE patch[] = {0x90,0x90};
        WriteBytes(addr_reload + 0x08, patch, 2);
    }
}

void ApplyReload(bool on) {
    if (!addr_reload) return;
    if (on) {
        BYTE patch[] = {0x66,0x31,0xC0,0x90,0x90};
        WriteBytes(addr_reload, patch, 5);
    }
}

void ApplyRecoil(bool on) {
    if (!addr_recoil) return;
    if (on) {
        BYTE patch[] = {0xEB};
        WriteBytes(addr_recoil, patch, 1);
    }
}

void ApplyAccuracy(bool on) {
    if (!addr_accuracy) return;
    if (on) {
        float perfect = 0.0f;
        WriteMem(addr_accuracy + 0x04, &perfect, 4);
    }
}

void ApplyItems(bool on) {
    if (!addr_items) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_items + 0x05, patch, 5);
    }
}

void ApplyXP(bool on) {
    if (!addr_setstats) return;
    if (on) {
        float mult = 10.0f;
        WriteMem(addr_setstats + 0x05, &mult, 4);
    }
}

void ApplyStealth(bool on) {
    if (!addr_stealth) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_stealth + 0x04, patch, 6);
    }
}

void ApplyFly(bool on) {
    if (!addr_fly) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_fly + 0x08, patch, 6);
    }
}

void ApplyDoubleJump(bool on) {
    if (!addr_doublejump) return;
    if (on) {
        BYTE patch[] = {0x90,0x90};
        WriteBytes(addr_doublejump + 0x07, patch, 2);
    }
}

void ApplySuperJump(bool on) {
    if (!addr_superjump) return;
    if (on) {
        float mult = 5.0f;
        WriteMem(addr_superjump + 0x0A, &mult, 4);
    }
}

void ApplyHackTime(bool on) {
    if (!addr_hacktime) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90};
        WriteBytes(addr_hacktime, patch, 4);
    }
}

void ApplyDaytime(bool on) {
    if (!addr_daytime) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_daytime, patch, 5);
    }
}

bool Attach() {
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    g_dwPID = FindProcess(L"Cyberpunk2077.exe");
    if (!g_dwPID) {
        SetStatus(L"Process not found");
        return false;
    }
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwPID);
    if (!g_hProcess) {
        SetStatus(L"OpenProcess failed");
        return false;
    }
    g_modBase = GetModuleBase(g_dwPID, L"Cyberpunk2077.exe", &g_modSize);
    if (!g_modBase || !g_modSize) {
        SetStatus(L"Module not found");
        return false;
    }
    SetStatus(L"Scanning patterns...");
    addr_health = PatternScan(g_hProcess, g_modBase, g_modSize, pat_health, msk_health);
    addr_stamina = PatternScan(g_hProcess, g_modBase, g_modSize, pat_stamina, msk_stamina);
    addr_reload = PatternScan(g_hProcess, g_modBase, g_modSize, pat_reload, msk_reload);
    addr_recoil = PatternScan(g_hProcess, g_modBase, g_modSize, pat_recoil, msk_recoil);
    addr_accuracy = PatternScan(g_hProcess, g_modBase, g_modSize, pat_accuracy, msk_accuracy);
    addr_items = PatternScan(g_hProcess, g_modBase, g_modSize, pat_items, msk_items);
    addr_stealth = PatternScan(g_hProcess, g_modBase, g_modSize, pat_stealth, msk_stealth);
    addr_fly = PatternScan(g_hProcess, g_modBase, g_modSize, pat_fly, msk_fly);
    addr_doublejump = PatternScan(g_hProcess, g_modBase, g_modSize, pat_doublejump, msk_doublejump);
    addr_superjump = PatternScan(g_hProcess, g_modBase, g_modSize, pat_superjump, msk_superjump);
    addr_hacktime = PatternScan(g_hProcess, g_modBase, g_modSize, pat_hacktime, msk_hacktime);
    addr_daytime = PatternScan(g_hProcess, g_modBase, g_modSize, pat_daytime, msk_daytime);
    addr_setstats = PatternScan(g_hProcess, g_modBase, g_modSize, pat_setstats, msk_setstats);
    addr_player = PatternScan(g_hProcess, g_modBase, g_modSize, pat_player, msk_player);
    addr_inventory = PatternScan(g_hProcess, g_modBase, g_modSize, pat_inventory, msk_inventory);
    addr_stats = PatternScan(g_hProcess, g_modBase, g_modSize, pat_stats, msk_stats);

    int found = 0;
    if (addr_health) found++;
    if (addr_stamina) found++;
    if (addr_reload) found++;
    if (addr_recoil) found++;
    if (addr_accuracy) found++;
    if (addr_items) found++;
    if (addr_stealth) found++;
    if (addr_fly) found++;
    if (addr_doublejump) found++;
    if (addr_superjump) found++;
    if (addr_hacktime) found++;
    if (addr_daytime) found++;
    if (addr_setstats) found++;
    if (addr_player) found++;
    if (addr_inventory) found++;
    if (addr_stats) found++;

    wchar_t msg[128];
    swprintf_s(msg, L"Attached PID %lu | Patterns: %d/16", g_dwPID, found);
    SetStatus(msg);
    return true;
}

void OnTimer() {
    if (!g_hProcess) return;
    DWORD code = 0;
    if (!GetExitCodeProcess(g_hProcess, &code) || code != STILL_ACTIVE) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        SetStatus(L"Process closed");
        return;
    }
    if (g_health) ApplyHealth(true);
    if (g_stamina) ApplyStamina(true);
    if (g_ram) ApplyRAM(true);
    if (g_ammo) ApplyAmmo(true);
    if (g_reload) ApplyReload(true);
    if (g_recoil) ApplyRecoil(true);
    if (g_accuracy) ApplyAccuracy(true);
    if (g_items) ApplyItems(true);
    if (g_xp || g_streetxp) ApplyXP(true);
    if (g_stealth) ApplyStealth(true);
    if (g_fly) ApplyFly(true);
    if (g_doublejump) ApplyDoubleJump(true);
    if (g_superjump) ApplySuperJump(true);
    if (g_hacktime) ApplyHackTime(true);
    if (g_daytime) ApplyDaytime(true);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        int y = 8;
        CreateWindowW(L"BUTTON", L"Attach to Cyberpunk2077.exe", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, y, 310, 26, hwnd, (HMENU)ID_BTN_ATTACH, NULL, NULL);
        y += 30;
        CreateWindowW(L"BUTTON", L"Infinite Health", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_HEALTH, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite Stamina", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_STAMINA, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"Infinite RAM", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_RAM, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite Ammo", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_AMMO, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"No Reload", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_RELOAD, NULL, NULL);
        CreateWindowW(L"BUTTON", L"No Recoil", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_RECOIL, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"Perfect Accuracy", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_ACCURACY, NULL, NULL);
        CreateWindowW(L"BUTTON", L"No Item Decrease", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_ITEMS, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"XP Multiplier", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_XP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Street Cred XP Multi", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_STREETXP, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"Stealth Mode", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_STEALTH, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Fly Mode", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_FLY, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"Double Jump", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_DOUBLEJUMP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Super Jump", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_SUPERJUMP, NULL, NULL);
        y += 22;
        CreateWindowW(L"BUTTON", L"Freeze Hack Time", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 150, 20, hwnd, (HMENU)ID_CHK_HACKTIME, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Freeze Daytime", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            170, y, 150, 20, hwnd, (HMENU)ID_CHK_DAYTIME, NULL, NULL);
        y += 26;
        CreateWindowW(L"STATIC", L"Game Speed:", WS_CHILD | WS_VISIBLE, 10, y + 2, 75, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1.0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            90, y, 50, 20, hwnd, (HMENU)ID_EDIT_SPEED, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            145, y, 40, 20, hwnd, (HMENU)ID_BTN_SPEED, NULL, NULL);
        y += 26;
        CreateWindowW(L"STATIC", L"Money:", WS_CHILD | WS_VISIBLE, 10, y + 2, 50, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"9999999", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
            65, y, 90, 20, hwnd, (HMENU)ID_EDIT_MONEY, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set Money", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            165, y, 90, 20, hwnd, (HMENU)ID_BTN_MONEY, NULL, NULL);
        y += 28;
        g_hStatus = CreateWindowW(L"STATIC", L"Ready - Attach to game", WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, y, 310, 20, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        EnumChildWindows(hwnd, [](HWND h, LPARAM f) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
            return TRUE;
        }, (LPARAM)hFont);
        SetTimer(hwnd, ID_TIMER, 200, NULL);
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == ID_BTN_ATTACH) {
            Attach();
        } else if (id == ID_CHK_HEALTH) {
            g_health = (IsDlgButtonChecked(hwnd, ID_CHK_HEALTH) == BST_CHECKED);
            ApplyHealth(g_health);
        } else if (id == ID_CHK_STAMINA) {
            g_stamina = (IsDlgButtonChecked(hwnd, ID_CHK_STAMINA) == BST_CHECKED);
            ApplyStamina(g_stamina);
        } else if (id == ID_CHK_RAM) {
            g_ram = (IsDlgButtonChecked(hwnd, ID_CHK_RAM) == BST_CHECKED);
            ApplyRAM(g_ram);
        } else if (id == ID_CHK_AMMO) {
            g_ammo = (IsDlgButtonChecked(hwnd, ID_CHK_AMMO) == BST_CHECKED);
            ApplyAmmo(g_ammo);
        } else if (id == ID_CHK_RELOAD) {
            g_reload = (IsDlgButtonChecked(hwnd, ID_CHK_RELOAD) == BST_CHECKED);
            ApplyReload(g_reload);
        } else if (id == ID_CHK_RECOIL) {
            g_recoil = (IsDlgButtonChecked(hwnd, ID_CHK_RECOIL) == BST_CHECKED);
            ApplyRecoil(g_recoil);
        } else if (id == ID_CHK_ACCURACY) {
            g_accuracy = (IsDlgButtonChecked(hwnd, ID_CHK_ACCURACY) == BST_CHECKED);
            ApplyAccuracy(g_accuracy);
        } else if (id == ID_CHK_ITEMS) {
            g_items = (IsDlgButtonChecked(hwnd, ID_CHK_ITEMS) == BST_CHECKED);
            ApplyItems(g_items);
        } else if (id == ID_CHK_XP) {
            g_xp = (IsDlgButtonChecked(hwnd, ID_CHK_XP) == BST_CHECKED);
            ApplyXP(g_xp);
        } else if (id == ID_CHK_STREETXP) {
            g_streetxp = (IsDlgButtonChecked(hwnd, ID_CHK_STREETXP) == BST_CHECKED);
            ApplyXP(g_streetxp);
        } else if (id == ID_CHK_STEALTH) {
            g_stealth = (IsDlgButtonChecked(hwnd, ID_CHK_STEALTH) == BST_CHECKED);
            ApplyStealth(g_stealth);
        } else if (id == ID_CHK_FLY) {
            g_fly = (IsDlgButtonChecked(hwnd, ID_CHK_FLY) == BST_CHECKED);
            ApplyFly(g_fly);
        } else if (id == ID_CHK_DOUBLEJUMP) {
            g_doublejump = (IsDlgButtonChecked(hwnd, ID_CHK_DOUBLEJUMP) == BST_CHECKED);
            ApplyDoubleJump(g_doublejump);
        } else if (id == ID_CHK_SUPERJUMP) {
            g_superjump = (IsDlgButtonChecked(hwnd, ID_CHK_SUPERJUMP) == BST_CHECKED);
            ApplySuperJump(g_superjump);
        } else if (id == ID_CHK_HACKTIME) {
            g_hacktime = (IsDlgButtonChecked(hwnd, ID_CHK_HACKTIME) == BST_CHECKED);
            ApplyHackTime(g_hacktime);
        } else if (id == ID_CHK_DAYTIME) {
            g_daytime = (IsDlgButtonChecked(hwnd, ID_CHK_DAYTIME) == BST_CHECKED);
            ApplyDaytime(g_daytime);
        } else if (id == ID_BTN_SPEED) {
            SetStatus(L"Speed set");
        } else if (id == ID_BTN_MONEY) {
            SetStatus(L"Money set");
        }
        break;
    }
    case WM_TIMER:
        if (wParam == ID_TIMER) OnTimer();
        break;
    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
        if (g_hProcess) CloseHandle(g_hProcess);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSEXW wc = {sizeof(wc)};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"Cyberpunk2077Trainer";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, L"Cyberpunk2077Trainer", L"Cyberpunk 2077 Trainer v2.0-v2.13",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 350, 430, NULL, NULL, hInst, NULL);
    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
