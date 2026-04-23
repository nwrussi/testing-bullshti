/*
 * Insider Threat Detection Agent
 * Windows C agent — native APIs only, no external dependencies.
 *
 * Monitors: process launches, USB events, clipboard content,
 *           active window titles, large network uploads, after-hours activity.
 *
 * Build: make  (MinGW)
 *   gcc -Wall -O2 -mwindows -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0600 \
 *       -o agent.exe agent.c \
 *       -lwinhttp -liphlpapi -lgdi32 -luser32 -lkernel32 -lole32 -ladvapi32 -lws2_32
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <dbt.h>
#include <wingdi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* =========================================================================
 * Configuration — edit these before building
 * ========================================================================= */

#define SERVER_HOST          L"127.0.0.1"
#define SERVER_PORT          5000
#define SERVER_PATH          L"/api/report"
#define USE_HTTPS            0           /* 1 = HTTPS, 0 = plain HTTP */
#define SKIP_CERT_VALIDATION 1           /* 1 = ignore self-signed certs (lab) */
#define PSK_KEY              L"changeme"
#define FLUSH_INTERVAL_MS    30000       /* 30 seconds between POSTs */
#define RING_SIZE            1000
#define SCREENSHOT_ON_HIGH   1           /* 1 = capture screenshot for HIGH risk events */
#define MAX_SCREENSHOT_B64   786432      /* ~600KB base64 ceiling */

/* After-hours: flag activity before 8am or after 6pm, or on weekends */
#define WORK_HOUR_START      8
#define WORK_HOUR_END        18

/* Network: alert if this many bytes uploaded in NETWORK_WINDOW_SAMPLES samples */
#define NETWORK_UPLOAD_THRESH_MB  10
#define NETWORK_SAMPLE_INTERVAL_MS 10000
#define NETWORK_WINDOW_SAMPLES     3     /* 3 × 10s = 30-second window */

/* =========================================================================
 * Structures
 * ========================================================================= */

typedef struct {
    char  event_type[32];
    char  data_json[2048];   /* pre-escaped JSON fragment (without outer braces) */
    char  timestamp[32];     /* ISO8601 local time */
    BOOL  after_hours;
    BOOL  is_high_risk;
    char *screenshot_b64;    /* HeapAlloc'd string or NULL */
} Event;

typedef struct {
    Event slots[RING_SIZE];
    int   head;
    int   tail;
    int   count;
    CRITICAL_SECTION cs;
} RingBuffer;

/* =========================================================================
 * Globals
 * ========================================================================= */

static RingBuffer g_ring;
static HINSTANCE  g_hInstance;

/* (GetIfTable used directly — always available in iphlpapi, no runtime loading needed) */

/* =========================================================================
 * Utilities
 * ========================================================================= */

static BOOL is_after_hours(void)
{
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    return (lt.wHour < WORK_HOUR_START || lt.wHour >= WORK_HOUR_END ||
            lt.wDayOfWeek == 0 || lt.wDayOfWeek == 6);
}

static void get_timestamp(char *buf, size_t len)
{
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    _snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02d",
              lt.wYear, lt.wMonth, lt.wDay,
              lt.wHour, lt.wMinute, lt.wSecond);
}

/*
 * Minimal JSON string escaper. Writes at most dst_len-1 bytes.
 * Handles: " \ / \b \f \n \r \t and control chars as \uXXXX.
 */
static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t d = 0;
    if (!src || !dst || dst_len == 0) return;

    for (size_t i = 0; src[i] && d + 8 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"')       { dst[d++] = '\\'; dst[d++] = '"';  }
        else if (c == '\\') { dst[d++] = '\\'; dst[d++] = '\\'; }
        else if (c == '\b') { dst[d++] = '\\'; dst[d++] = 'b';  }
        else if (c == '\f') { dst[d++] = '\\'; dst[d++] = 'f';  }
        else if (c == '\n') { dst[d++] = '\\'; dst[d++] = 'n';  }
        else if (c == '\r') { dst[d++] = '\\'; dst[d++] = 'r';  }
        else if (c == '\t') { dst[d++] = '\\'; dst[d++] = 't';  }
        else if (c < 0x20) {
            d += _snprintf(dst + d, dst_len - d, "\\u%04x", c);
        } else {
            dst[d++] = (char)c;
        }
    }
    dst[d] = '\0';
}

/*
 * Convert wide string to UTF-8 in a caller-supplied buffer.
 */
static void wcs_to_utf8(const wchar_t *src, char *dst, int dst_len)
{
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dst_len, NULL, NULL);
}

/* =========================================================================
 * Base64 encoder (RFC 4648, no line wrapping)
 * ========================================================================= */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const BYTE *src, DWORD src_len, char *dst, DWORD dst_buf)
{
    DWORD i = 0, d = 0;
    DWORD out_len = ((src_len + 2) / 3) * 4;
    if (!dst || dst_buf < out_len + 1) return;

    while (i < src_len) {
        DWORD remaining = src_len - i;
        BYTE b0 = src[i];
        BYTE b1 = (remaining > 1) ? src[i + 1] : 0;
        BYTE b2 = (remaining > 2) ? src[i + 2] : 0;

        dst[d++] = B64_TABLE[b0 >> 2];
        dst[d++] = B64_TABLE[((b0 & 0x03) << 4) | (b1 >> 4)];
        dst[d++] = (remaining > 1) ? B64_TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
        dst[d++] = (remaining > 2) ? B64_TABLE[b2 & 0x3F] : '=';
        i += 3;
    }
    dst[d] = '\0';
}

/* =========================================================================
 * Ring buffer operations
 * ========================================================================= */

static void ring_push(const Event *ev)
{
    EnterCriticalSection(&g_ring.cs);
    {
        int slot = g_ring.tail;
        /* If full, the oldest slot is evicted and its screenshot freed */
        if (g_ring.count == RING_SIZE) {
            if (g_ring.slots[g_ring.head].screenshot_b64) {
                HeapFree(GetProcessHeap(), 0, g_ring.slots[g_ring.head].screenshot_b64);
                g_ring.slots[g_ring.head].screenshot_b64 = NULL;
            }
            g_ring.head = (g_ring.head + 1) % RING_SIZE;
        } else {
            g_ring.count++;
        }
        g_ring.slots[slot] = *ev;
        g_ring.tail = (g_ring.tail + 1) % RING_SIZE;
    }
    LeaveCriticalSection(&g_ring.cs);
}

/*
 * Drain all pending events into a caller-supplied array.
 * Returns the number of events drained.
 * Caller must free any non-NULL screenshot_b64 pointers after use.
 */
static int ring_drain(Event *out, int out_max)
{
    int drained = 0;
    EnterCriticalSection(&g_ring.cs);
    {
        int count = (g_ring.count < out_max) ? g_ring.count : out_max;
        for (int i = 0; i < count; i++) {
            out[i] = g_ring.slots[g_ring.head];
            g_ring.head = (g_ring.head + 1) % RING_SIZE;
        }
        g_ring.count -= count;
        drained = count;
    }
    LeaveCriticalSection(&g_ring.cs);
    return drained;
}

/* =========================================================================
 * Screenshot capture
 * ========================================================================= */

#if SCREENSHOT_ON_HIGH
/*
 * Capture the foreground window (or full desktop as fallback).
 * Returns a HeapAlloc'd base64 BMP string, or NULL on failure.
 * Caller must HeapFree the result.
 */
static char *capture_screenshot(void)
{
    int      cx, cy;
    HDC      hdcSrc  = NULL;
    HDC      hdcMem  = NULL;
    HBITMAP  hBmp    = NULL;
    HGDIOBJ  hOld    = NULL;
    BYTE    *pixels  = NULL;
    BYTE    *bmp_buf = NULL;
    char    *b64_buf = NULL;
    HWND     hwnd;
    RECT     rc;

    hwnd = GetForegroundWindow();

    if (hwnd && GetWindowRect(hwnd, &rc)) {
        cx = rc.right  - rc.left;
        cy = rc.bottom - rc.top;
    } else {
        cx = 0; cy = 0;
    }

    /* Clamp to 1920×1080 to keep payload reasonable */
    if (cx > 1920) cx = 1920;
    if (cy > 1080) cy = 1080;

    /* Fall back to full desktop if window is zero-area */
    if (cx <= 0 || cy <= 0) {
        hwnd = NULL;
        cx = GetSystemMetrics(SM_CXSCREEN);
        cy = GetSystemMetrics(SM_CYSCREEN);
        if (cx > 1920) cx = 1920;
        if (cy > 1080) cy = 1080;
    }

    hdcSrc = GetDC(hwnd);
    if (!hdcSrc) goto cleanup;

    hdcMem = CreateCompatibleDC(hdcSrc);
    if (!hdcMem) goto cleanup;

    hBmp = CreateCompatibleBitmap(hdcSrc, cx, cy);
    if (!hBmp) goto cleanup;

    hOld = SelectObject(hdcMem, hBmp);

    /* Try PrintWindow first (captures DWM-composited content correctly) */
    BOOL captured = FALSE;
    if (hwnd) {
        captured = PrintWindow(hwnd, hdcMem, 0x2 /* PW_RENDERFULLCONTENT */);
    }
    if (!captured) {
        captured = BitBlt(hdcMem, 0, 0, cx, cy, hdcSrc, 0, 0, SRCCOPY);
    }
    if (!captured) goto cleanup;

    /* Build DIB */
    BITMAPINFOHEADER bih;
    ZeroMemory(&bih, sizeof(bih));
    bih.biSize        = sizeof(BITMAPINFOHEADER);
    bih.biWidth       = cx;
    bih.biHeight      = -cy;   /* top-down */
    bih.biPlanes      = 1;
    bih.biBitCount    = 24;
    bih.biCompression = BI_RGB;
    DWORD row_bytes   = ((cx * 3 + 3) & ~3);
    DWORD pixel_bytes = row_bytes * (DWORD)cy;

    pixels = (BYTE *)HeapAlloc(GetProcessHeap(), 0, pixel_bytes);
    if (!pixels) goto cleanup;

    if (!GetDIBits(hdcMem, hBmp, 0, cy, pixels, (BITMAPINFO *)&bih, DIB_RGB_COLORS))
        goto cleanup;

    /* Assemble BMP file: BITMAPFILEHEADER + BITMAPINFOHEADER + pixels */
    DWORD bmp_size = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pixel_bytes;
    bmp_buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bmp_size);
    if (!bmp_buf) goto cleanup;

    BITMAPFILEHEADER bfh;
    bfh.bfType      = 0x4D42; /* "BM" */
    bfh.bfSize      = bmp_size;
    bfh.bfReserved1 = 0;
    bfh.bfReserved2 = 0;
    bfh.bfOffBits   = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    memcpy(bmp_buf,                            &bfh, sizeof(bfh));
    memcpy(bmp_buf + sizeof(bfh),              &bih, sizeof(bih));
    memcpy(bmp_buf + sizeof(bfh) + sizeof(bih), pixels, pixel_bytes);

    /* Base64 encode */
    DWORD b64_len = ((bmp_size + 2) / 3) * 4 + 1;
    if (b64_len > MAX_SCREENSHOT_B64) goto cleanup;  /* too large, skip */

    b64_buf = (char *)HeapAlloc(GetProcessHeap(), 0, b64_len);
    if (!b64_buf) goto cleanup;

    base64_encode(bmp_buf, bmp_size, b64_buf, b64_len);

cleanup:
    if (pixels)  HeapFree(GetProcessHeap(), 0, pixels);
    if (bmp_buf) HeapFree(GetProcessHeap(), 0, bmp_buf);
    if (hOld)    SelectObject(hdcMem, hOld);
    if (hBmp)    DeleteObject(hBmp);
    if (hdcMem)  DeleteDC(hdcMem);
    if (hdcSrc)  ReleaseDC(hwnd, hdcSrc);

    return b64_buf;  /* NULL on any failure */
}
#endif /* SCREENSHOT_ON_HIGH */

/* =========================================================================
 * Event helpers
 * ========================================================================= */

static void emit_event(const char *event_type, const char *data_json_fragment,
                       BOOL high_risk)
{
    Event ev;
    ZeroMemory(&ev, sizeof(ev));

    _snprintf(ev.event_type, sizeof(ev.event_type), "%s", event_type);
    _snprintf(ev.data_json,  sizeof(ev.data_json),  "%s", data_json_fragment);
    get_timestamp(ev.timestamp, sizeof(ev.timestamp));
    ev.after_hours  = is_after_hours();
    ev.is_high_risk = high_risk;

#if SCREENSHOT_ON_HIGH
    if (high_risk) {
        ev.screenshot_b64 = capture_screenshot();  /* may be NULL */
    }
#endif

    ring_push(&ev);
}

/* =========================================================================
 * Monitor: Process launches
 * ========================================================================= */

#define MAX_TRACKED_PIDS 4096

static DWORD WINAPI ThreadProc_Process(LPVOID lpParam)
{
    (void)lpParam;
    DWORD prev_pids[MAX_TRACKED_PIDS] = {0};
    int   prev_count = 0;
    char  tmp[2048];
    char  name_utf8[512];
    char  name_esc[512];

    while (1) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            Sleep(2000);
            continue;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        DWORD cur_pids[MAX_TRACKED_PIDS] = {0};
        int   cur_count = 0;

        if (Process32FirstW(snap, &pe)) {
            do {
                if (cur_count < MAX_TRACKED_PIDS)
                    cur_pids[cur_count++] = pe.th32ProcessID;

                /* Check if this PID is new */
                BOOL found = FALSE;
                for (int i = 0; i < prev_count; i++) {
                    if (prev_pids[i] == pe.th32ProcessID) { found = TRUE; break; }
                }
                if (!found && prev_count > 0) {
                    /* New process — emit event */
                    wcs_to_utf8(pe.szExeFile, name_utf8, sizeof(name_utf8));
                    json_escape(name_utf8, name_esc, sizeof(name_esc));
                    _snprintf(tmp, sizeof(tmp),
                              "\"name\":\"%s\",\"pid\":%lu",
                              name_esc, (unsigned long)pe.th32ProcessID);
                    emit_event("PROCESS", tmp, FALSE);
                }
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);

        memcpy(prev_pids, cur_pids, cur_count * sizeof(DWORD));
        prev_count = cur_count;

        Sleep(2000);
    }
    return 0;
}

/* =========================================================================
 * Monitor: USB devices (message-only window + WM_DEVICECHANGE)
 * ========================================================================= */

static LRESULT CALLBACK UsbWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_DEVICECHANGE) {
        const char *ev_type = NULL;
        const char *dev_event = NULL;

        if (wParam == DBT_DEVICEARRIVAL) {
            ev_type  = "USB_INSERT";
            dev_event = "arrival";
        } else if (wParam == DBT_DEVICEREMOVECOMPLETE) {
            ev_type  = "USB_REMOVE";
            dev_event = "removal";
        }

        if (ev_type) {
            char tmp[256];
            const char *dev_type = "unknown";
            if (lParam) {
                PDEV_BROADCAST_HDR hdr = (PDEV_BROADCAST_HDR)lParam;
                if (hdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
                    dev_type = "mass_storage";
                else if (hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
                    dev_type = "device_interface";
                else if (hdr->dbch_devicetype == DBT_DEVTYP_PORT)
                    dev_type = "port";
            }
            _snprintf(tmp, sizeof(tmp),
                      "\"event\":\"%s\",\"device_type\":\"%s\"",
                      dev_event, dev_type);
            emit_event(ev_type, tmp, FALSE);
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI ThreadProc_Usb(LPVOID lpParam)
{
    (void)lpParam;

    /* Register a unique window class for the hidden USB monitor window */
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = UsbWndProc;
    wc.hInstance     = g_hInstance;
    wc.lpszClassName = L"ITD_UsbMonitor";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        0, L"ITD_UsbMonitor", NULL, 0,
        0, 0, 0, 0,
        HWND_MESSAGE, NULL, g_hInstance, NULL);

    if (!hwnd) return 1;

    /* Register for device notifications */
    DEV_BROADCAST_DEVICEINTERFACE dbi;
    ZeroMemory(&dbi, sizeof(dbi));
    dbi.dbcc_size       = sizeof(dbi);
    dbi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    RegisterDeviceNotificationW(hwnd, &dbi, DEVICE_NOTIFY_WINDOW_HANDLE |
                                             DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);

    MSG msg;
    while (GetMessageW(&msg, hwnd, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

/* =========================================================================
 * Monitor: Clipboard — keyword detection
 * ========================================================================= */

static const wchar_t *CLIP_KEYWORDS[] = {
    L"password",
    L"passwd",
    L"passphrase",
    L"secret",
    L"api_key",
    L"apikey",
    L"access_key",
    L"secret_key",
    L"aws_secret",
    L"private key",
    L"-----begin",
    L"social security",
    L"ssn",
    L"credit card",
    L"card number",
    L"cvv",
    L"authorization",
    L"bearer",
    L"token",
    NULL
};

/* Case-insensitive wide string search (simple O(n*m)) */
static const wchar_t *wcsistr(const wchar_t *haystack, const wchar_t *needle)
{
    if (!*needle) return haystack;
    size_t nlen = wcslen(needle);
    for (; *haystack; haystack++) {
        if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
                           haystack, (int)nlen, needle, (int)nlen) == CSTR_EQUAL)
            return haystack;
    }
    return NULL;
}

static DWORD WINAPI ThreadProc_Clipboard(LPVOID lpParam)
{
    (void)lpParam;
    char kw_utf8[256];
    char kw_esc[256];
    char tmp[512];

    while (1) {
        Sleep(2000);

        if (!OpenClipboard(NULL)) continue;

        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (!hData) { CloseClipboard(); continue; }

        wchar_t *text = (wchar_t *)GlobalLock(hData);
        if (!text)  { CloseClipboard(); continue; }

        size_t text_len = wcslen(text);

        for (int k = 0; CLIP_KEYWORDS[k]; k++) {
            if (wcsistr(text, CLIP_KEYWORDS[k])) {
                wcs_to_utf8(CLIP_KEYWORDS[k], kw_utf8, sizeof(kw_utf8));
                json_escape(kw_utf8, kw_esc, sizeof(kw_esc));
                _snprintf(tmp, sizeof(tmp),
                          "\"keyword\":\"%s\",\"char_count\":%u",
                          kw_esc, (unsigned)text_len);
                emit_event("CLIPBOARD", tmp, TRUE);
                break;  /* one event per clipboard change */
            }
        }

        GlobalUnlock(hData);
        CloseClipboard();
    }
    return 0;
}

/* =========================================================================
 * Monitor: Active window title
 * ========================================================================= */

static DWORD WINAPI ThreadProc_Window(LPVOID lpParam)
{
    (void)lpParam;
    HWND    last_hwnd = NULL;
    wchar_t title_w[512];
    char    title_utf8[1024];
    char    title_esc[1024];
    char    tmp[1200];

    while (1) {
        Sleep(3000);

        HWND hwnd = GetForegroundWindow();
        if (!hwnd || hwnd == last_hwnd) continue;
        last_hwnd = hwnd;

        int len = GetWindowTextW(hwnd, title_w, (int)(sizeof(title_w)/sizeof(wchar_t)));
        if (len <= 0) continue;

        wcs_to_utf8(title_w, title_utf8, sizeof(title_utf8));
        /* Truncate to 256 chars for the JSON payload */
        title_utf8[256] = '\0';
        json_escape(title_utf8, title_esc, sizeof(title_esc));

        _snprintf(tmp, sizeof(tmp), "\"title\":\"%s\"", title_esc);
        emit_event("WINDOW", tmp, FALSE);
    }
    return 0;
}

/* =========================================================================
 * Monitor: Large network uploads
 * ========================================================================= */

static DWORD WINAPI ThreadProc_Network(LPVOID lpParam)
{
    (void)lpParam;

    /*
     * Use GetIfTable (Win2000+, always in MinGW iphlpapi).
     * dwOutOctets is a 32-bit DWORD; wraps at ~4GB but that is fine for a
     * 30-second measurement window (would require >1 Gbps sustained to wrap).
     */
    ULONG samples[NETWORK_WINDOW_SAMPLES];
    int   sample_idx = 0;
    char  tmp[128];
    DWORD buf_size   = 0;

    while (1) {
        Sleep(NETWORK_SAMPLE_INTERVAL_MS);

        /* First call: get required buffer size */
        GetIfTable(NULL, &buf_size, FALSE);
        PMIB_IFTABLE pTable = (PMIB_IFTABLE)HeapAlloc(GetProcessHeap(), 0, buf_size);
        if (!pTable) continue;

        if (GetIfTable(pTable, &buf_size, FALSE) != NO_ERROR) {
            HeapFree(GetProcessHeap(), 0, pTable);
            continue;
        }

        ULONG total_out = 0;
        for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
            total_out += pTable->table[i].dwOutOctets;
        }
        HeapFree(GetProcessHeap(), 0, pTable);

        samples[sample_idx % NETWORK_WINDOW_SAMPLES] = total_out;
        sample_idx++;

        /* Need a full window before computing delta */
        if (sample_idx < NETWORK_WINDOW_SAMPLES) continue;

        /* newest = slot we just wrote; oldest = slot we'll overwrite next */
        int newest_slot = (sample_idx - 1) % NETWORK_WINDOW_SAMPLES;
        int oldest_slot =  sample_idx      % NETWORK_WINDOW_SAMPLES;

        ULONG newest = samples[newest_slot];
        ULONG oldest = samples[oldest_slot];
        /* Handle 32-bit counter wrap */
        ULONG delta = (newest >= oldest) ? (newest - oldest)
                                         : (ULONG_MAX - oldest + newest + 1);

        ULONG thresh = (ULONG)NETWORK_UPLOAD_THRESH_MB * 1024UL * 1024UL;
        if (delta >= thresh) {
            _snprintf(tmp, sizeof(tmp),
                      "\"bytes_out\":%lu,\"window_sec\":%d",
                      (unsigned long)delta,
                      NETWORK_SAMPLE_INTERVAL_MS / 1000 * NETWORK_WINDOW_SAMPLES);
            emit_event("NETWORK_UPLOAD", tmp, TRUE);
        }
    }
    return 0;
}

/* =========================================================================
 * Flush thread: build JSON payload and POST to server
 * ========================================================================= */

/* Maximum events to drain per flush cycle */
#define FLUSH_BATCH_MAX 200

static void build_payload(Event *events, int count, char *buf, size_t buf_size,
                          const char *hostname_esc)
{
    size_t pos = 0;
    pos += _snprintf(buf + pos, buf_size - pos,
                     "{\"hostname\":\"%s\",\"events\":[", hostname_esc);

    for (int i = 0; i < count && pos < buf_size - 256; i++) {
        if (i > 0) {
            buf[pos++] = ',';
        }

        char data_esc[2200];
        /* data_json is already a valid JSON fragment — embed directly */
        /* But we still need to verify it won't break the outer JSON;
           the monitors write safe fragments, so this is just a safety truncate */
        _snprintf(data_esc, sizeof(data_esc), "%s", events[i].data_json);

        size_t remaining = buf_size - pos;
        int written = _snprintf(buf + pos, remaining,
            "{\"event_type\":\"%s\","
            "\"timestamp\":\"%s\","
            "\"after_hours\":%s,"
            "\"data_json\":{%s}",
            events[i].event_type,
            events[i].timestamp,
            events[i].after_hours ? "true" : "false",
            data_esc);

        if (written < 0 || (size_t)written >= remaining) break;
        pos += (size_t)written;

#if SCREENSHOT_ON_HIGH
        if (events[i].screenshot_b64 && buf_size - pos > 32) {
            size_t b64_len = strlen(events[i].screenshot_b64);
            if (pos + b64_len + 20 < buf_size) {
                pos += _snprintf(buf + pos, buf_size - pos,
                                 ",\"screenshot_b64\":\"%s\"",
                                 events[i].screenshot_b64);
            }
        }
#endif

        if (pos < buf_size - 2) {
            buf[pos++] = '}';
        }
    }

    if (pos < buf_size - 3) {
        buf[pos++] = ']';
        buf[pos++] = '}';
        buf[pos]   = '\0';
    } else {
        buf[buf_size - 1] = '\0';
    }
}

static BOOL do_post(const char *payload, DWORD payload_len)
{
    BOOL    success = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD   dwStatus  = 0;
    DWORD   dwSize    = sizeof(DWORD);

    hSession = WinHttpOpen(
        L"ITD-Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) goto done;

    hConnect = WinHttpConnect(
        hSession,
        SERVER_HOST,
        (INTERNET_PORT)SERVER_PORT,
        0);
    if (!hConnect) goto done;

    DWORD open_flags = 0;
#if USE_HTTPS
    open_flags = WINHTTP_FLAG_SECURE;
#endif

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        SERVER_PATH,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        open_flags);
    if (!hRequest) goto done;

#if USE_HTTPS && SKIP_CERT_VALIDATION
    {
        DWORD certFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &certFlags, sizeof(certFlags));
    }
#endif

    /* Force TLS 1.2 */
#if USE_HTTPS
    {
        DWORD tlsFlags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
                         &tlsFlags, sizeof(tlsFlags));
    }
#endif

    /* Headers: auth key + content type */
    WinHttpAddRequestHeaders(
        hRequest,
        L"X-Agent-Key: " PSK_KEY L"\r\nContent-Type: application/json\r\n",
        (DWORD)-1L,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)payload, payload_len,
            payload_len, 0))
        goto done;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto done;

    /* Check HTTP status */
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &dwStatus, &dwSize, WINHTTP_NO_HEADER_INDEX);

    success = (dwStatus == 200 || dwStatus == 201);

done:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return success;
}

static DWORD WINAPI ThreadProc_Flush(LPVOID lpParam)
{
    (void)lpParam;

    static Event batch[FLUSH_BATCH_MAX];
    /* 2MB payload buffer — large enough for a full batch + screenshots */
    static char payload[2 * 1024 * 1024];

    /* Get local hostname */
    wchar_t hostname_w[MAX_COMPUTERNAME_LENGTH + 1];
    char    hostname_utf8[256];
    char    hostname_esc[256];
    DWORD   hn_len = sizeof(hostname_w) / sizeof(wchar_t);
    if (!GetComputerNameW(hostname_w, &hn_len))
        wcscpy(hostname_w, L"unknown");
    wcs_to_utf8(hostname_w, hostname_utf8, sizeof(hostname_utf8));
    json_escape(hostname_utf8, hostname_esc, sizeof(hostname_esc));

    while (1) {
        Sleep(FLUSH_INTERVAL_MS);

        int count = ring_drain(batch, FLUSH_BATCH_MAX);
        if (count <= 0) continue;

        build_payload(batch, count, payload, sizeof(payload), hostname_esc);

        BOOL ok = do_post(payload, (DWORD)strlen(payload));
        if (!ok) {
            OutputDebugStringA("[ITD] POST failed — events lost\n");
        }

        /* Free screenshot buffers regardless of POST result */
        for (int i = 0; i < count; i++) {
            if (batch[i].screenshot_b64) {
                HeapFree(GetProcessHeap(), 0, batch[i].screenshot_b64);
                batch[i].screenshot_b64 = NULL;
            }
        }
    }
    return 0;
}

/* =========================================================================
 * Persistence: HKCU Run key
 * ========================================================================= */

static void install_persistence(void)
{
    HKEY    hKey;
    wchar_t exe_path[MAX_PATH];

    if (!GetModuleFileNameW(NULL, exe_path, MAX_PATH)) return;

    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;

    RegSetValueExW(hKey, L"SystemHealthMonitor", 0, REG_SZ,
                   (const BYTE *)exe_path,
                   (DWORD)((wcslen(exe_path) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
}

/* =========================================================================
 * WinMain entry point
 * ========================================================================= */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    g_hInstance = hInstance;

    /* Initialize ring buffer */
    ZeroMemory(&g_ring, sizeof(g_ring));
    InitializeCriticalSection(&g_ring.cs);

    /* Install persistence (HKCU Run key) */
    install_persistence();

    /* Start monitor threads */
    HANDLE threads[6];
    threads[0] = CreateThread(NULL, 0, ThreadProc_Process,  NULL, 0, NULL);
    threads[1] = CreateThread(NULL, 0, ThreadProc_Usb,      NULL, 0, NULL);
    threads[2] = CreateThread(NULL, 0, ThreadProc_Clipboard,NULL, 0, NULL);
    threads[3] = CreateThread(NULL, 0, ThreadProc_Window,   NULL, 0, NULL);
    threads[4] = CreateThread(NULL, 0, ThreadProc_Network,  NULL, 0, NULL);
    threads[5] = CreateThread(NULL, 0, ThreadProc_Flush,    NULL, 0, NULL);

    /* Run a message loop on the main thread to stay alive and process
     * any messages dispatched to the main thread's queue. */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Cleanup (reached only if WM_QUIT is posted) */
    for (int i = 0; i < 6; i++) {
        if (threads[i]) {
            TerminateThread(threads[i], 0);
            CloseHandle(threads[i]);
        }
    }
    DeleteCriticalSection(&g_ring.cs);
    return 0;
}
