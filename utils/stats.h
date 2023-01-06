#pragma once

#include <map>
#include <set>
#include "format_util.h"

#define ENTROPY_TRESHOLD 1.5

#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)
#define IS_PRINTABLE(c) ((c >= 0x20 && c < 0x7f) || IS_ENDLINE(c))

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
        T getMostFrequentValue(IN std::map<T, size_t>& histogram)
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
                : size(0), offset(0), entropy(0), is_printable(false)
            {
            }

            // Copy constructor
            ChunkStats(const ChunkStats& p1)
                : size(p1.size), offset(p1.offset), histogram(p.histogram.begin(), p.histogram.end())
                entropy(p1.entropy), is_printable(p1.is_printable)
            {
            }

            ChunkStats(size_t _offset, size_t _size)
                : size(_size), offset(_offset), is_printable(false)
            {
            }

            void append(T val)
            {
                size++;
                histogram[val]++;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"offset\" : ");
                outs << std::hex << "\"" << offset << "\"";
                outs << ",\n";
                OUT_PADDED(outs, level, "\"size\" : ");
                outs << std::hex << "\"" << size << "\"";
                outs << ",\n";
                OUT_PADDED(outs, level, "\"is_printable\" : ");
                outs << std::dec << is_printable;

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
                is_printable = isAllPrintable(histogram);
            }

            double entropy;
            size_t size;
            size_t offset;
            bool is_printable;
            std::map<T, size_t> histogram;
        };

        template <typename T>
        struct AreaStats {
            AreaStats()
            {
            }

            // Copy constructor
            AreaStats(const AreaStats& p1)
                : currArea(p1.currArea), biggestChunk(p1.biggestChunk)
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
                OUT_PADDED(outs, level, "},\n");
                // print chunk stats
                OUT_PADDED(outs, level, "\"biggest_chunk\" : {\n");
                biggestChunk.fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
            }

            bool isFilled()
            {
                return (currArea.size != 0) ? true : false;
            }

            void summarize()
            {
                currArea.summarize();
                biggestChunk.summarize();
            }

            ChunkStats<T> currArea; // stats from the whole area
            ChunkStats<T> biggestChunk;//< biggest continuous chunk (not interrupted by a defined delimiter)
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

                const T kDelim = 0; // delimiter of continuous chunks
                stats.biggestChunk = ChunkStats<T>();
                //
                ChunkStats<T> currChunk;
                T lastVal = 0;
                for (size_t dataIndex = 0; dataIndex < elements; ++dataIndex) {
                    const T val = data[dataIndex];
                    stats.currArea.append(val);

                    if (val == kDelim) {
                        if (currChunk.size > stats.biggestChunk.size) { // delimiter found, finish the chunk
                            stats.biggestChunk = currChunk;
                        }
                        currChunk = ChunkStats<T>(dataIndex, 0);
                    }
                    if (lastVal == kDelim && val != kDelim) {
                        // start a new chunk
                        currChunk = ChunkStats<T>(dataIndex, 0);
                    }
                    currChunk.append(val);
                    lastVal = val;
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

