#include "iat_block.h"
#include <peconv.h>

bool IATBlock::makeCoverage(IN peconv::ExportsMapper* exportsMap)
{
	std::set<IATThunksSeries*>::iterator itr;

	size_t covered = 0;
	for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); itr++) {
		IATThunksSeries* series = *itr;
		if (series->makeCoverage(exportsMap)) {
			covered++;
		}
	}
	isCoverageComplete = (covered == this->thunkSeries.size());
	return isCoverageComplete;
}

bool IATBlock::isCovered()
{
	return isCoverageComplete;
}
