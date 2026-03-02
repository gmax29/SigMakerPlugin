#pragma once

#include <Windows.h>
#include "sdk.h" 

extern "C" {
    __declspec(dllexport) BOOL CE_CONV CEPlugin_GetVersion(CE_PLUGIN_VERSION* version, int version_size);
    __declspec(dllexport) BOOL CE_CONV CEPlugin_InitializePlugin(CE_EXPORTED_FUNCTIONS* exports, int pluginid);
    __declspec(dllexport) BOOL CE_CONV CEPlugin_DisablePlugin();
}