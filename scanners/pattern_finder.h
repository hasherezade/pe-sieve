#pragma once

#include <windows.h>
#include <sstream>

#include <sig_finder.h>
#include "../utils/byte_buffer.h"
#include "../utils/format_util.h"
#include "../utils/artefacts_util.h"
#include "../utils/crc32.h"

namespace pesieve {
	
	//! Base class for the matched patterns.
	class MatchesInfo {
	public:
		MatchesInfo()
		{
		}

		void appendMatch(util::t_pattern_matched& m)
		{
			int id = m.patternId;
			if (m.name.length()) {
				id = util::calcCRC32(m.name.c_str(), m.name.length());
			}
			auto found = this->matches.find(id);
			if (found == this->matches.end()) {
				this->matches[id] = m;
				return;
			}
			util::t_pattern_matched& found_m = found->second;
			found_m.offsets.insert(m.offsets.begin(),m.offsets.end());
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
				util::t_pattern_matched& m = itr->second;
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
			if (m.name.length()) {
				OUT_PADDED(outs, level, "\"name\" : ");
				outs << "\"" <<  m.name << "\"";
				outs << ",\n";
			}
			else {
				OUT_PADDED(outs, level, "\"pattern\" : ");
				outs << std::dec << m.patternId;
				outs << ",\n";
				OUT_PADDED(outs, level, "\"group\" : ");
				outs << std::dec << m.groupId;
				outs << ",\n";
			}
			OUT_PADDED(outs, level, "\"offsets\" : [ ");
			size_t oI = 0;
			for (auto itr = m.offsets.begin(); itr != m.offsets.end(); ++itr, ++oI) {
				outs << std::hex << "\"" << *itr << "\"";
				if (oI < (m.offsets.size() - 1)) {
					outs << ", ";
				}
			}
			outs << " ]\n";
		}

		std::map<DWORD, util::t_pattern_matched> matches;


	}; // AreaStats
	sig_ma::matched_set find_matching_patterns(const BYTE* loadedData, size_t loadedSize, bool stopOnFirstMatch = true);

	bool fill_matching(const BYTE* loadedData, size_t loadedSize, size_t startOffset, MatchesInfo& _matchesInfo);
};
