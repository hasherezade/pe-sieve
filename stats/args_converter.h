#pragma once

#include <pe_sieve_types.h>
#include "stats_analyzer.h"

namespace pesieve {

	namespace stats {

		inline int argsToRules(const pesieve::t_stat_rules stats)
		{
			using namespace pesieve;

			int rules = stats::RULE_NONE;

			switch (stats) {
			case t_stat_rules::STATS_ALL:
				rules = stats::RULE_CODE | stats::RULE_OBFUSCATED | stats::RULE_ENCRYPTED; break;
			case t_stat_rules::STATS_CODE:
				rules = stats::RULE_CODE; break;
			case t_stat_rules::STATS_OBFUSCATED:
				rules = stats::RULE_OBFUSCATED | stats::RULE_ENCRYPTED; break;
			}
			return rules;
		}

	}; //namespace stats
}; // namespace pesieve


