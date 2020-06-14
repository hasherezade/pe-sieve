#pragma once

#include <peconv.h>

namespace pesieve {

	class PeBuffer {
	public:
		PeBuffer()
			: vBuf(nullptr), vBufSize(0), moduleBase(0), relocBase(0)
		{
		}

		~PeBuffer()
		{
			freeBuffer();
		}

		bool isFilled()
		{
			return (vBuf && vBufSize > 0);
		}

		bool isValidPe()
		{
			if (!vBuf) return false;
			if (peconv::get_nt_hdrs(vBuf, vBufSize)) {
				return true;
			}
			return false;
		}

		// Returns the size of the internal buffer
		size_t getBufferSize()
		{
			return vBufSize;
		}

		// Reads content from the remote process into a buffer. Automatically allocates sutiable buffer.
		bool readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize);

		// Resizes internal buffer into a new size.
		// The internal buffer must be non empty.
		bool resizeBuffer(size_t new_size);

		// Requires the internal buffer to contain a valid PE. Resizes the last section of the PE, to make it fit the new Image Size.
		// The internal buffer must be non empty, and not smaller than the new Image Size.
		bool resizeLastSection(size_t new_img_size);

		// Requires the internal buffer to contain a valid PE. 
		// Dumps the PE into a file with a given name.
		bool dumpPeToFile(IN std::string dumpFileName,
			IN OUT peconv::t_pe_dump_mode &dumpMode,
			IN OPTIONAL const peconv::ExportsMapper* exportsMap = NULL,
			OUT OPTIONAL peconv::ImpsNotCovered *notCovered = NULL
		);

		bool dumpToFile(IN std::string dumpFileName);

		ULONGLONG getModuleBase()
		{
			return moduleBase;
		}

		ULONGLONG getRelocBase()
		{
			return relocBase;
		}

		void setRelocBase(ULONGLONG reloc_base)
		{
			relocBase = reloc_base;
		}

	protected:
		bool _readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize);

		size_t calcRemoteImgSize(HANDLE process_hndl, ULONGLONG module_base);

		bool allocBuffer(const size_t pe_vsize)
		{
			freeBuffer();
			vBuf = peconv::alloc_aligned(pe_vsize, PAGE_READWRITE);
			if (!vBuf) {
				return false;
			}
			vBufSize = pe_vsize;
			return true;
		}

		void freeBuffer()
		{
			peconv::free_aligned(vBuf);
			vBuf = nullptr;
			vBufSize = 0;
			moduleBase = 0;
			relocBase = 0;
		}

		BYTE * vBuf;
		size_t vBufSize;
		ULONGLONG moduleBase;
		ULONGLONG relocBase;

		friend class ImpReconstructor;
		friend class PeReconstructor;
	};

}; //namespace pesieve
