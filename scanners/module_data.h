#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>

#include <peconv.h>
#include "../utils/format_util.h"

namespace pesieve {

	class ModuleData {

	public:
		ModuleData(HANDLE _processHandle, HMODULE _module)
			: processHandle(_processHandle), moduleHandle(_module),
			is_module_named(false), original_size(0), original_module(nullptr),
			is_dot_net(false)
		{
			memset(szModName, 0, MAX_PATH);
			loadModuleName();
		}

		ModuleData(HANDLE _processHandle, HMODULE _module, std::string module_name)
			: processHandle(_processHandle), moduleHandle(_module),
			is_module_named(false), original_size(0), original_module(nullptr),
			is_dot_net(false)
		{
			memset(szModName, 0, MAX_PATH);
			memcpy(this->szModName, module_name.c_str(), module_name.length());
		}

		~ModuleData()
		{
			peconv::free_pe_buffer(original_module, original_size);
		}

		bool is64bit()
		{
			if (original_module == nullptr) {
				return false;
			}
			return peconv::is64bit(original_module);
		}

		bool isDotNet() { return this->is_dot_net; }

		ULONGLONG rvaToVa(DWORD rva)
		{
			return reinterpret_cast<ULONGLONG>(this->moduleHandle) + rva;
		}

		DWORD vaToRva(ULONGLONG va)
		{
			ULONGLONG module_base = reinterpret_cast<ULONGLONG>(this->moduleHandle);
			if (va < module_base) {
				return NULL; // not this module
			}
			if (va > module_base + this->original_size) {
				return NULL; // not this module
			}
			ULONGLONG diff = (va - module_base);
			return static_cast<DWORD>(diff);
		}

		bool isInitialized()
		{
			return original_module != nullptr;
		}

		ULONGLONG getHdrImageBase()
		{
			if (!original_module) return 0;
			return peconv::get_image_base((const BYTE*)original_module);
		}

		bool loadOriginal();

		bool switchToWow64Path();
		bool reloadWow64();
		bool relocateToBase(ULONGLONG new_base);

		HANDLE processHandle;
		HMODULE moduleHandle;
		char szModName[MAX_PATH];
		bool is_module_named;

		PBYTE original_module;
		size_t original_size;

	protected:
		bool _loadOriginal(bool disableFSredir);
		bool loadModuleName();
		bool isDotNetManagedCode();
		bool is_dot_net;

		friend class PeSection;
	};

	// the module loaded within the scanned process
	class RemoteModuleData
	{
	public:
		static std::string getModuleName(HANDLE _processHandle, HMODULE _modBaseAddr);
		static std::string getMappedName(HANDLE _processHandle, LPVOID _modBaseAddr);

		RemoteModuleData(HANDLE _processHandle, HMODULE _modBaseAddr)
			: processHandle(_processHandle), modBaseAddr(_modBaseAddr),
			imgBuffer(nullptr), imgBufferSize(0)
		{
			isHdrReady = false;
			memset(headerBuffer, 0, peconv::MAX_HEADER_SIZE);
			init();
		}

		virtual ~RemoteModuleData()
		{
			freeFullImage();
		}

		bool isSectionEntry(const size_t section_number);
		bool isSectionExecutable(const size_t section_number);
		bool hasExecutableSection();
		bool isInitialized()
		{
			if (!isHdrReady && !init()) {
				return false;
			}
			return true;
		}

		size_t getHdrImageSize()
		{
			if (!isHdrReady) return 0;
			return peconv::get_image_size((const BYTE*)headerBuffer);
		}

		ULONGLONG getHdrImageBase()
		{
			if (!isHdrReady) return 0;
			return peconv::get_image_base((const BYTE*)headerBuffer);
		}

		size_t getModuleSize()
		{
			if (imgBufferSize) {
				return imgBufferSize;
			}
			return getHdrImageSize();
		}

		size_t getHeaderSize()
		{
			return peconv::MAX_HEADER_SIZE;
		}

		bool loadFullImage();
		bool isFullImageLoaded() { return (imgBuffer != nullptr) && (imgBufferSize != 0); }
		ULONGLONG getRemoteSectionVa(const size_t section_num);

		ULONGLONG getModuleBase()
		{
			return (ULONGLONG)modBaseAddr;
		}

		BYTE headerBuffer[peconv::MAX_HEADER_SIZE];

	protected:
		bool init();
		bool loadHeader();
		size_t calcImgSize();

		bool _loadFullImage(size_t v_size);

		void freeFullImage()
		{
			peconv::free_pe_buffer(imgBuffer);
			imgBuffer = nullptr;
			imgBufferSize = 0;
		}

		HANDLE processHandle;
		HMODULE modBaseAddr;

		BYTE *imgBuffer;
		size_t imgBufferSize;

	private:
		bool isHdrReady;

		friend class PeSection;
		friend class IATScanner;
	};

}; //namespace pesieve

