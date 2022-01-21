#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>
#include <set>

#include <peconv.h>
#include "../utils/format_util.h"
#include "module_cache.h"

namespace pesieve {

	//! Loads a module from the disk, corresponding to the module in the scanned process' memory.
	class ModuleData {

	public:
		ModuleData(HANDLE _processHandle, HMODULE _module, bool _isPEBConnected, bool _useCache)
			: processHandle(_processHandle), moduleHandle(_module),
			isPEBConnected(_isPEBConnected), useCache(_useCache),
			is_module_named(false), original_size(0), original_module(nullptr),
			is_dot_net(false)
		{
			memset(szModName, 0, MAX_PATH);
			loadModuleName();
		}

		ModuleData(HANDLE _processHandle, HMODULE _module, std::string module_name, bool _useCache)
			: processHandle(_processHandle), moduleHandle(_module), useCache(_useCache),
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

		ULONGLONG rvaToVa(DWORD rva, ULONGLONG module_base = 0)
		{
			if (module_base == 0) {
				module_base = reinterpret_cast<ULONGLONG>(this->moduleHandle);
			}
			return module_base + rva;
		}

		DWORD vaToRva(ULONGLONG va, ULONGLONG module_base = 0)
		{
			if (module_base == 0) {
				module_base = reinterpret_cast<ULONGLONG>(this->moduleHandle);
			}
			if (va < module_base) {
				return 0; // not this module
			}
			if (va > module_base + this->original_size) {
				return 0; // not this module
			}
			ULONGLONG diff = (va - module_base);
			return static_cast<DWORD>(diff);
		}

		bool isModuleInPEBList()
		{
			return isPEBConnected;
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
		bool loadRelocatedFields(std::set<DWORD>& fields_rvas);
		bool loadImportThunks(std::set<DWORD>& fields_rvas);
		bool loadImportsList(peconv::ImportsCollection &collection);

		HANDLE processHandle;
		HMODULE moduleHandle;
		char szModName[MAX_PATH];
		bool is_module_named;

		PBYTE original_module;
		size_t original_size;

	protected:
		bool _loadOriginal(bool disableFSredir);
		bool loadModuleName();
		bool autoswichIfWow64Mapping();
		bool isDotNetManagedCode();

		bool is_dot_net;
		bool isPEBConnected;
		bool useCache;

		friend class PeSection;
	};

	//! Buffers the data from the module loaded in the scanned process into the local memory.
	class RemoteModuleData
	{
	public:
		static std::string getModuleName(HANDLE _processHandle, HMODULE _modBaseAddr);
		static std::string getMappedName(HANDLE _processHandle, LPVOID _modBaseAddr);

		RemoteModuleData(HANDLE _processHandle, bool _isRefl, HMODULE _modBaseAddr)
			: processHandle(_processHandle), isReflection(_isRefl), modBaseAddr(_modBaseAddr),
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
		bool isSectionExecutable(const size_t section_number, bool allow_data, bool allow_inaccessible);
		bool hasExecutableSection(bool allow_data, bool allow_inaccessible);
		bool isInitialized()
		{
			if (!isHdrReady && !init()) {
				return false;
			}
			return true;
		}

		bool is64bit()
		{
			if (!isHdrReady) return false;
			return peconv::is64bit(headerBuffer);
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
		bool loadImportsList(peconv::ImportsCollection& collection);

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
		const bool isReflection;
		HMODULE modBaseAddr;

		BYTE *imgBuffer;
		size_t imgBufferSize;

	private:
		bool isHdrReady;

		friend class PeSection;
		friend class IATScanner;
	};

}; //namespace pesieve

