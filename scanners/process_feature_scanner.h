#pragma once

#include <windows.h>
#include <map>

#include <peconv.h>
#include "scan_report.h"

namespace pesieve {

	//!  A base class for all the scanners checking appropriate process' features.
	class ProcessFeatureScanner {

	public:
		ProcessFeatureScanner(HANDLE _processHandle)
			: processHandle(_processHandle)
		{
		}

		virtual ~ProcessFeatureScanner() {}

		/**
		Perform the scan on the remote process
		\return a pointer to an object of the class inherited from ModuleScanReport
		*/
		virtual ModuleScanReport* scanRemote() = 0;

	protected:
		HANDLE processHandle;
	};

}; //namespace pesieve
