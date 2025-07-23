#ifndef MINHOOK_H
#define MINHOOK_H
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MH_ALL_HOOKS ((LPVOID)-1)

typedef enum {
    MH_OK = 0,
    MH_ERROR_ALREADY_CREATED = -1,
    MH_ERROR_NOT_CREATED = -2,
} MH_STATUS;

MH_STATUS MH_Initialize(void);
MH_STATUS MH_Uninitialize(void);
MH_STATUS MH_CreateHook(LPVOID target, LPVOID detour, LPVOID *original);
MH_STATUS MH_EnableHook(LPVOID target);
MH_STATUS MH_DisableHook(LPVOID target);
MH_STATUS MH_RemoveHook(LPVOID target);

#ifdef __cplusplus
}
#endif

#endif // MINHOOK_H
