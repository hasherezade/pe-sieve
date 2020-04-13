#include "iat_scanner.h"
#include <peconv.h>

IATScanReport* IATScanner::scanRemote()
{
	if (!remoteModData.isInitialized() || !remoteModData.isFullImageLoaded()) {
		std::cerr << "[-] Failed to initialize remote module" << std::endl;
		return nullptr;
	}

	peconv::ImpsNotCovered not_covered;
	peconv::fix_imports(remoteModData.imgBuffer, remoteModData.imgBufferSize, exportsMap, &not_covered);

	t_scan_status status = SCAN_NOT_SUSPICIOUS;
	if (not_covered.addresses.size() > 0) {
		status = SCAN_SUSPICIOUS;
	}

	IATScanReport *report = new IATScanReport(processHandle, remoteModData.modBaseAddr, remoteModData.getModuleSize(), moduleData.szModName);
	report->status = status;
	report->hookedCount = not_covered.addresses.size();
	report->notCovered = not_covered;
	return report;
}
