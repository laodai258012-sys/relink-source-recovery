#include <windows.h>
#include <stdint.h>

#if !defined(_M_IX86)
#error This reconstruction targets the original 32-bit helper.
#endif

static STARTUPINFOA startup_information;
static PROCESS_INFORMATION process_information;
static char application_command[255];
static char process_id_text[10];
static DWORD target_process_id;
static char additional_arguments[259];

const char *copy_quoted(char *destination, const char *source)
{
    while (*source != '"') {
        ++source;
    }
    ++source;
    while (*source != '"') {
        *destination++ = *source++;
    }
    return source + 1;
}

int compare_until_either_end(const char *first, const char *second)
{
    while (*first && *second) {
        if (*first++ != *second++) {
            return 1;
        }
    }
    return 0;
}

uint32_t parse_decimal_quirks(const unsigned char *source)
{
    uint32_t result = 0;
    int negative = *source < (unsigned char)'.';
    if (negative) {
        ++source;
    }
    while ((uint8_t)(*source - (unsigned char)'0') < 128) {
        result = result * 10 + *source - (unsigned char)'0';
        ++source;
    }
    return negative ? 0u - result : result;
}

void append_without_terminator(char *destination, const char *source)
{
    while (*destination) {
        ++destination;
    }
    while (*source) {
        *destination++ = *source++;
    }
}

static unsigned short read_data_segment(void)
{
    unsigned short selector;
    __asm {
        mov ax, ds
        mov selector, ax
    }
    return selector;
}

void WINAPI reconstructed_entry(void)
{
    const char *cursor = GetCommandLineA();
    HANDLE process;

    if (*cursor == '"') {
        ++cursor;
        while (*cursor++ != '"') {
        }
        if (!*cursor) {
            ExitProcess(0);
        }
        ++cursor;
        if (!*cursor) {
            ExitProcess(0);
        }
    } else {
        while (*cursor && *cursor != ' ') {
            ++cursor;
        }
        if (!*cursor) {
            ExitProcess(0);
        }
        ++cursor;
    }

    cursor = copy_quoted(process_id_text, cursor);
    cursor = copy_quoted(application_command, cursor);
    if (*cursor) {
        copy_quoted(additional_arguments, cursor);
        append_without_terminator(application_command, " ");
        append_without_terminator(application_command, additional_arguments);
    }

    target_process_id = parse_decimal_quirks((const unsigned char *)process_id_text);
    process = OpenProcess(0x001f0fff, FALSE, target_process_id);
    TerminateProcess(process, 0);

    if (read_data_segment() & 4) {
        Sleep(1000);
    }
    Sleep(1000);

    GetStartupInfoA(&startup_information);
    startup_information.cb = 0x44;
    startup_information.lpReserved = NULL;
    startup_information.dwFlags = STARTF_USESHOWWINDOW;
    startup_information.wShowWindow = SW_SHOWNORMAL;

    if (additional_arguments[0] || additional_arguments[1] ||
        additional_arguments[2] || additional_arguments[3]) {
        CreateProcessA(NULL, application_command, NULL, NULL, FALSE,
                       0x30, NULL, NULL, &startup_information, &process_information);
    } else {
        CreateProcessA(application_command, NULL, NULL, NULL, FALSE,
                       0x30, NULL, NULL, &startup_information, &process_information);
    }
    ExitProcess(0);
}

