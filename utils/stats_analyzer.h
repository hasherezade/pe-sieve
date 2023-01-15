#pragma once

#include "stats.h"

#define CODE_RULE "possible_code"

namespace pesieve {

    namespace util {

        //---

        class RuleMatcher
        {
        public:
            RuleMatcher(std::string _name)
                : name(_name), matched(false)
            {
            }

            bool isMatching(IN const AreaStats<BYTE>& stats)
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

            virtual bool _isMatching(IN const AreaStats<BYTE>& stats) = 0;

            bool matched;
        };


        struct RuleMatchersSet
        {
            RuleMatchersSet();
            ~RuleMatchersSet();

            std::vector< RuleMatcher*> matchers;
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

            const virtual bool toJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"area_info\" : {\n");
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

        bool isSuspicious(IN const AreaStats<BYTE>& stats, IN RuleMatchersSet& matchersSet, OUT AreaInfo& info);

    } //namespace util

}; // namespace pesieve
