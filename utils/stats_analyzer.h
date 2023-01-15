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
        //---

        struct AreaInfo
        {
            AreaInfo()
            {
                _fillMatchers();
            }

            // Copy constructor
            /*AreaInfo(const AreaInfo& p1)
            {
            }*/

            ~AreaInfo()
            {
                _clearMatchers();
            }

            void _fillMatchers();

            void _clearMatchers()
            {
                for (auto itr = matchers.begin(); itr != matchers.end(); ++itr) {
                    RuleMatcher* m = *itr;
                    if (!m) continue;
                    delete m;
                }
                matchers.clear();
            }

            bool hasMatchAt(const std::string& ruleName)
            {
                for (auto itr = matchers.begin(); itr != matchers.end(); ++itr) {
                    RuleMatcher* m = *itr;
                    if (!m) continue;
                    if (m->name  == ruleName) {
                        return m->isMatched();
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
                size_t matched = 0;
                for (auto itr = matchers.begin(); itr != matchers.end(); ++itr) {
                    RuleMatcher* m = *itr;
                    if (!m || !m->isMatched()) continue;
                    if (matched > 0) {
                        outs << ",\n";
                    }
                    matched++;
                    OUT_PADDED(outs, level, "\"" + m->name + "\" : ");
                    outs << std::dec << true;
                }
            }

            std::vector< RuleMatcher*> matchers;
        };

        bool isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info);

    } //namespace util

}; // namespace pesieve
