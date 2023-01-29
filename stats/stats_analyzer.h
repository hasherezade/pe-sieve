#pragma once

#include "stats.h"

#define CODE_RULE "possible_code"

namespace pesieve {

    namespace stats {

        size_t fillCodeStrings(OUT std::set<std::string>& codeStrings);

        //---

        enum RuleType
        {
            RULE_NONE = 0,
            RULE_CODE = 1,
            RULE_TEXT = 2,
            RULE_OBFUSCATED = 4,
            RULE_ENCRYPTED = 8
        };

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
            RuleMatchersSet(DWORD ruleTypes)
            {
                initRules(ruleTypes);
            }

            ~RuleMatchersSet()
            {
                deleteMatchers();
            }

            void initRules(DWORD ruleTypes);

            void deleteMatchers()
            {
                for (auto itr = matchers.begin(); itr != matchers.end(); ++itr) {
                    RuleMatcher* m = *itr;
                    if (!m) continue;
                    delete m;
                }
                matchers.clear();
            }

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

        size_t fetchPeakValues(IN const ChunkStats<BYTE>& currArea, IN double stdDev, int devCount, OUT std::set<BYTE>& peaks);

        size_t valuesNotBelowMean(IN const ChunkStats<BYTE>& currArea, double mean);

        double getPrintableRatio(IN const AreaStats<BYTE>& stats);

        bool isSuspicious(IN const AreaStats<BYTE>& stats, IN RuleMatchersSet& matchersSet, OUT AreaInfo& info);

    } //namespace util

}; // namespace pesieve
