#pragma once

#include <string>
#include <map>
#include <set>
#include <vector>
#include "format_util.h"

#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)
#define IS_PRINTABLE(c) ((c >= 0x20 && c < 0x7f) || IS_ENDLINE(c))

#define SCAN_STRINGS

namespace pesieve {

    namespace util {

        // Shannon's Entropy calculation based on: https://stackoverflow.com/questions/20965960/shannon-entropy
        template <typename T>
        double calcShannonEntropy(std::map<T, size_t>& histogram, size_t totalSize)
        {
            if (!totalSize) return 0;
            double entropy = 0;
            for (auto it = histogram.begin(); it != histogram.end(); ++it) {
                double p_x = (double)it->second / totalSize;
                if (p_x > 0) entropy -= p_x * log(p_x) / log(2);
            }
            return entropy;
        }

        template <typename T>
        std::string hexdumpValue(const BYTE* in_buf, const size_t max_size)
        {
            std::stringstream ss;
            for (size_t i = 0; i < max_size; i++) {
                ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)in_buf[i];
            }
            return ss.str();
        }

        // return the most frequent value
        template <typename T>
        T getMostFrequentValue(IN const std::map<T, size_t>& histogram)
        {
            T mVal = 0;
            size_t mFreq = 0;
            for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                if (itr->second > mFreq) {
                    mFreq = itr->second;
                    mVal = itr->first;
                }
            }
            return mVal;
        }

        // return the number of occurrencies
        template <typename T>
        size_t getMostFrequentValues(IN std::map<T, size_t>& histogram, OUT std::set<T> &values)
        {
            // find the highest frequency:
            size_t mFreq = 0;
            for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                if (itr->second > mFreq) {
                    mFreq = itr->second;
                }
            }
            if (!mFreq) return mFreq;
            // find all the values matching this frequency
            for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                if (itr->second == mFreq) {
                    values.insert(itr->first);
                }
            }
            return mFreq;
        }

        template <typename T>
        bool isAllPrintable(IN std::map<T, size_t>& histogram)
        {
            if (!histogram.size()) return false;

            bool is_printable = true;
            for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                T val = itr->first;
                if (val && !IS_PRINTABLE(val)) {
                    is_printable = false;
                    break;
                }
            }
            return is_printable;
        }

        template <typename T>
        struct ChunkStats {
            //
            ChunkStats() 
                : size(0), offset(0), entropy(0), longestStr(0), prevVal(0), stringsCount(0)
            {
            }

            ChunkStats(size_t _offset, size_t _size)
                : size(_size), offset(_offset), entropy(0), longestStr(0), prevVal(0), stringsCount(0)
            {
            }

            // Copy constructor
            ChunkStats(const ChunkStats& p1)
                : size(p1.size), offset(p1.offset), 
                entropy(p1.entropy), longestStr(p1.longestStr), lastStr(p1.lastStr), prevVal(p1.prevVal), stringsCount(p1.stringsCount),
                histogram(p1.histogram),
                frequencies(p1.frequencies)
#ifdef _KEEP_STR
                , allStrings(p1.allStrings)
#endif //_KEEP_STR
            {
            }

            void append(T val)
            {
#ifdef SCAN_STRINGS
                if (IS_PRINTABLE(val)) {
                    lastStr += char(val);
                }
                else {
                    if (val == 0) { //clean ending
                        if (lastStr.length()) {
                            stringsCount++;
                        }
                        if (lastStr.length() > longestStr) {
                            longestStr = lastStr.length();
#ifdef _KEEP_STR
                            allStrings.push_back(lastStr);
#endif //_KEEP_STR
                            //std::cout << "-----> lastStr:" << lastStr  << "\n";
                        }
                    }
                    lastStr.clear();
                }
#endif // SCAN_STRINGS
                size++;
                histogram[val]++;
                prevVal = val;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"offset\" : ");
                outs << std::hex << "\"" << offset << "\"";
                outs << ",\n";
                OUT_PADDED(outs, level, "\"size\" : ");
                outs << std::hex << "\"" << size << "\"";
#ifdef SCAN_STRINGS
                outs << ",\n";
                OUT_PADDED(outs, level, "\"str_count\" : ");
                outs << std::dec << stringsCount;
                outs << ",\n";
                OUT_PADDED(outs, level, "\"str_longest_len\" : ");
                outs << std::dec << longestStr;
#endif // SCAN_STRINGS

                std::set<T> values;
                size_t freq = getMostFrequentValues(histogram, values);
                if (freq && values.size()) {
                    outs << ",\n";
                    OUT_PADDED(outs, level, "\"most_freq_occurrence\" : ");
                    outs << std::dec << freq;
                    outs << ",\n";
                    OUT_PADDED(outs, level, "\"most_freq_val_count\" : ");
                    outs << std::dec << values.size();
                    outs << ",\n";
                    OUT_PADDED(outs, level, "\"most_freq_val\" : ");
                    T mVal = *(values.begin());
                    outs << std::hex << "\"" << hexdumpValue<BYTE>((BYTE*)&mVal, sizeof(T)) << "\"";
                }
                outs << ",\n";
                OUT_PADDED(outs, level, "\"entropy\" : ");
                outs << std::dec << entropy;
            }

            void summarize()
            {
                entropy = calcShannonEntropy(histogram, size);

                for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                    frequencies[itr->second] = itr->first;
                }
            }

            double entropy;
            size_t size;
            size_t offset;

            T prevVal;
            size_t longestStr; // the longest ASCII string in the chunk

            std::string lastStr;
            size_t stringsCount;
            std::map<T, size_t> histogram;
            std::map<size_t, T> frequencies;
#ifdef _KEEP_STR
            std::vector< std::string > allStrings;
#endif
        };

        template <typename T>
        struct AreaStats {
            AreaStats()
            {
            }

            // Copy constructor
            AreaStats(const AreaStats& p1)
                : currArea(p1.currArea)
            {
            }

            const virtual bool toJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"stats\" : {\n");
                fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
                return true;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"full_area\" : {\n");
                currArea.fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
            }

            bool isFilled() const
            {
                return (currArea.size != 0) ? true : false;
            }

            void summarize()
            {
                currArea.summarize();
            }

            ChunkStats<T> currArea; // stats from the whole area
        };

        template <typename T>
        class AreaStatsCalculator {
        public:
            AreaStatsCalculator(T _data[], size_t _elements)
                :data(_data), elements(_elements)
            {
            }

            bool fill(AreaStats<T> &stats)
            {
                if (!data || !elements) return false;

                T lastVal = 0;
                for (size_t dataIndex = 0; dataIndex < elements; ++dataIndex) {
                    const T val = data[dataIndex];
                    stats.currArea.append(val);
                }
                stats.summarize();
                return true;
            }

        private:
            T *data;
            size_t  elements;
        };

    }; // namespace util

}; //namespace pesieve

