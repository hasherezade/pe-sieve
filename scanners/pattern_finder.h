#pragma once

#include <windows.h>
#include <sstream>

#include <sig_finder.h>
#include "../utils/byte_buffer.h"
#include "../utils/format_util.h"
#include "../utils/artefacts_util.h"

namespace pesieve {

	//! Base class for the matched patterns.
	class MatchesInfo {
	public:
		MatchesInfo()
		{
		}

		void appendMatch(util::t_pattern_matched& m)
		{
			this->matches.push_back(m);
		}

		size_t size()
		{
			return this->matches.size();
		}

		const virtual bool toJSON(std::stringstream& outs, size_t level)
		{
			OUT_PADDED(outs, level, "\"matches\" : [\n");
			size_t i = 0;
			for (auto itr = matches.begin(); itr != matches.end(); ++itr, ++i) {
				OUT_PADDED(outs, level, "{\n");
				util::t_pattern_matched& m = *itr;
				fieldToJSON(outs, level + 1, m);
				OUT_PADDED(outs, level, "}");
				if (i < (matches.size() - 1)) {
					outs << ",";
				}
				outs << "\n";
			}
			OUT_PADDED(outs, level, "]");
			return true;
		}

	protected:
		const virtual void fieldToJSON(std::stringstream& outs, size_t level, util::t_pattern_matched &m)
		{
			OUT_PADDED(outs, level, "\"pattern\" : ");
			outs << std::dec << m.patternId;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"group\" : ");
			outs << std::dec << m.groupId ;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"offsets\" : [ ");
			outs << std::hex << "\"" << m.offset << "\"";
			outs << " ]\n";

		}

		std::vector<util::t_pattern_matched> matches;

	}; // AreaStats
	sig_ma::matched_set find_matching_patterns(BYTE* loadedData, size_t loadedSize, bool stopOnFirstMatch = true);

	bool fill_matching(const BYTE* loadedData, size_t loadedSize, MatchesInfo& _matchesInfo);
};
