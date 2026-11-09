/* hello_upx.c - benign target for the UPX unpacking walkthrough on uplinkless.github.io.
 * Prints fixed text, upper-cases a fixed string (user32), prints the processor
 * architecture value (kernel32) and hashes a fixed string with SHA-256 (advapi32).
 * It reads no user, host, path, time or network information.
 */
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

static const char kMessage[] = "uplinkless UPX demo";

static int print_sha256(const char *text)
{
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD len = sizeof digest;
    int ok = 0;

    if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash) &&
        CryptHashData(hash, (const BYTE *)text, (DWORD)strlen(text), 0) &&
        CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0)) {
        printf("sha256: ");
        for (DWORD i = 0; i < len; i++)
            printf("%02x", digest[i]);
        printf("\n");
        ok = 1;
    }
    if (hash)
        CryptDestroyHash(hash);
    if (prov)
        CryptReleaseContext(prov, 0);
    return ok;
}

int main(void)
{
    char upper[sizeof kMessage];
    SYSTEM_INFO si;

    memcpy(upper, kMessage, sizeof kMessage);
    CharUpperA(upper);
    GetSystemInfo(&si);
    printf("%s\n", kMessage);
    printf("upper: %s\n", upper);
    printf("arch: %u\n", (unsigned)si.wProcessorArchitecture);
    return print_sha256(kMessage) ? 0 : 1;
}
