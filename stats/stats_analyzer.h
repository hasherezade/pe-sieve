#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "stats.h"
#include "multi_stats.h"
#include "stats_util.h"

#define CODE_RULE "possible_code"

namespace pesieve {

	namespace stats {

		size_t fillCodeStrings(OUT std::set<std::string>& codeStrings);

		size_t fetchPeakValues(IN const ChunkStats& currArea, IN double stdDev, int devCount, OUT std::set<BYTE>& peaks);

		size_t valuesNotBelowMean(IN const ChunkStats& currArea, double mean);

		double getPrintableRatio(IN const AreaMultiStats& stats);

	}; //namespace stats

	//---

	class RuleMatcher
	{
	public:

		enum RuleType
		{
			RULE_NONE = 0,
			RULE_CODE = 1,
			RULE_TEXT = 2,
			RULE_OBFUSCATED = 4,
			RULE_ENCRYPTED = 8
		};

		RuleMatcher(std::string _name)
			: name(_name), matched(false)
		{
		}

		bool isMatching(IN const AreaMultiStats& stats)
		{
			matched = _isMatching(stats);
			return matched;
		}

		bool isMatched()
		{
			return matched;
		}

		std::string name;

	protected:

		virtual bool _isMatching(IN const AreaMultiStats& stats) = 0;

		bool matched;
	};

	//---

	struct AreaInfo
	{
		AreaInfo()
		{
		}

		// Copy constructor
		AreaInfo(const AreaInfo& p1)
			: matchedRules(p1.matchedRules)
		{
		}

		bool hasMatchAt(const std::string& ruleName)
		{
			for (auto itr = matchedRules.begin(); itr != matchedRules.end(); ++itr) {
				std::string name = *itr;
				if (name == ruleName) {
					return true;
				}
			}
			return false;
		}

		bool hasAnyMatch()
		{
			return (matchedRules.size()) != 0 ? true : false;
		}

		const virtual bool toJSON(std::stringstream& outs, size_t level)
		{
			OUT_PADDED(outs, level, "\"stats_verdict\" : {\n");
			fieldsToJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
		{
			size_t count = 0;
			for (auto itr = matchedRules.begin(); itr != matchedRules.end(); ++itr) {
				std::string ruleName = *itr;
				if (count > 0) {
					outs << ",\n";
				}
				count++;
				OUT_PADDED(outs, level, "\"" + ruleName + "\" : ");
				outs << std::dec << true;
			}
		}

		std::vector<std::string> matchedRules;
	};

	//
	struct RuleMatchersSet
	{
		RuleMatchersSet(DWORD ruleTypes)
		{
			initRules(ruleTypes);
		}

		~RuleMatchersSet()
		{
			deleteMatchers();
		}

		void initRules(DWORD ruleTypes);

		size_t findMatches(IN const AreaMultiStats& stats, OUT AreaInfo& info);

		void deleteMatchers()
		{
			for (auto itr = matchers.begin(); itr != matchers.end(); ++itr) {
				RuleMatcher* m = *itr;
				if (!m) continue;
				delete m;
			}
			matchers.clear();
		}

		std::vector< RuleMatcher* > matchers;
	};

}; // namespace pesieve
