#pragma once

#include <windows.h>
#include "entropy.h"
#include "stats.h"

namespace pesieve {

	class AreaEntropyStats : public AreaStats {
	public:
		AreaEntropyStats()
			: AreaStats(),
			entropy(0.0)
		{
		}

		// Copy constructor
		AreaEntropyStats(const AreaEntropyStats& p1)
		{
			area_size = p1.area_size;
			area_start = p1.area_start;
			entropy = p1.entropy;
		}

		void _appendVal(BYTE val)
		{
			histogram[val]++;
		}

		virtual void summarize()
		{
			entropy = stats::calcShannonEntropy(histogram, area_size);
		}

		std::map<BYTE, size_t> histogram;
		double entropy;

	protected:

		const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
		{
			OUT_PADDED(outs, level, "\"area_start\" : ");
			outs << "\"" << std::hex << area_start << "\"";
			outs << ",\n";
			OUT_PADDED(outs, level, "\"area_size\" : ");
			outs << "\"" << std::hex << area_size << "\"";
			outs << ",\n";
			OUT_PADDED(outs, level, "\"entropy\" : ");
			outs << std::dec << entropy;
		}

		friend class AreaStatsCalculator;

	}; // AreaStats

};
