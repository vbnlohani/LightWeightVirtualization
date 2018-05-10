#pragma once
#include <Windows.h>

extern HMODULE moduleHandle;
extern LPVOID pTarget_1;
extern LPVOID pTarget_2;


extern HMODULE moduleHandle2;
extern LPVOID pTarget_3;
extern LPVOID pTarget_4;
extern LPVOID pTarget_5;

int create_hooks();
int destroy_hooks();