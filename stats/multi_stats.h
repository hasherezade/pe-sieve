#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <set>

#include "entropy.h"
#include "stats.h"
#include "stats_util.h"
#include "../utils/format_util.h"
#include "../utils/path_util.h"

namespace pesieve {

	//! Settings defining what type of stats should be collected.
	struct MultiStatsSettings : public StatsSettings
	{
	public:
		MultiStatsSettings()
			: StatsSettings()
		{
		}

		// Copy constructor
		MultiStatsSettings(const MultiStatsSettings& p1)
			: watchedStrings(p1.watchedStrings)
		{
		}

		bool isFilled()
		{
			return (watchedStrings.size() != 0) ? true : false;
		}

		//! Searches a given substring among the `watchedStrings`. If the substring found, return the corresponding watched string containing the substring. 
		std::string hasWatchedSubstring(std::string& lastStr)
		{
			for (auto itr = watchedStrings.begin(); itr != watchedStrings.end(); ++itr) {
				const std::string s = *itr;
				if (lastStr.find(s) != std::string::npos && s.length()) {
					//std::cout << "[+] KEY for string: " << lastStr << " found: " << s << "\n";
					return s; // the current string contains searched string
				}
			}
			//std::cout << "[-] KEY for string: " << lastStr << " NOT found!\n";
			return "";
		}

		std::set<std::string> watchedStrings;
	};

	//! Statistics from a block of data.
	struct ChunkStats {
		//
		ChunkStats()
			: size(0), offset(0), entropy(0), longestStr(0), prevVal(0),
			stringsCount(0), cleanStringsCount(0), settings(nullptr)
		{
		}

		ChunkStats(size_t _offset, size_t _size)
			: size(_size), offset(_offset), entropy(0), longestStr(0), prevVal(0),
			stringsCount(0), cleanStringsCount(0), settings(nullptr)
		{
		}

		// Copy constructor
		ChunkStats(const ChunkStats& p1)
			: size(p1.size), offset(p1.offset),
			entropy(p1.entropy), longestStr(p1.longestStr), lastStr(p1.lastStr), prevVal(p1.prevVal),
			stringsCount(p1.stringsCount), cleanStringsCount(p1.cleanStringsCount)
		{
#ifdef _KEEP_STR
			allStrings = p1.allStrings;
#endif //_KEEP_STR
			histogram = p1.histogram;
			frequencies = p1.frequencies;
			settings = p1.settings;
			foundStrings = p1.foundStrings;
			fillSettings(p1.settings);
		}

		void fillSettings(MultiStatsSettings* _settings)
		{
			settings = _settings;
		}

		void appendVal(BYTE val)
		{

			size++;
			histogram[val]++;
			prevVal = val;

			// scan strings:
			const bool isPrint = IS_PRINTABLE(val);
			if (isPrint) {
				lastStr += char(val);
			}
			else {
				const bool isClean = (val == 0) ? true : false; //terminated cleanly?
				finishLastStr(isClean);
				lastStr.clear();
			}
		}

		void finishLastStr(bool isClean)
		{
			if (lastStr.length() < 2) {
				return;
			}
			stringsCount++;
			if (isClean) cleanStringsCount++;

			if (settings) {
				std::string key = settings->hasWatchedSubstring(lastStr);
				if (key.length()) {
					foundStrings[key]++; // the current string contains searched string
				}
			}
#ifdef _KEEP_STR
			allStrings.push_back(lastStr);
#endif //_KEEP_STR
			//std::cout << "-----> lastStr:" << lastStr << "\n";
			if (lastStr.length() > longestStr) {
				longestStr = lastStr.length();
			}
			lastStr.clear();
		}

		const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
		{
			OUT_PADDED(outs, level, "\"offset\" : ");
			outs << std::hex << "\"" << offset << "\"";
			outs << ",\n";
			OUT_PADDED(outs, level, "\"size\" : ");
			outs << std::hex << "\"" << size << "\"";
			outs << ",\n";
			OUT_PADDED(outs, level, "\"charset_size\" : ");
			outs << std::dec << histogram.size();

			std::set<BYTE> values;
			size_t freq = stats::getMostFrequentValues<BYTE>(frequencies, values);
			if (freq && values.size()) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"most_freq_vals\" : ");
				outs << std::hex << "\"";
				for (auto itr = values.begin(); itr != values.end(); ++itr) {
					BYTE mVal = *itr;
					outs << util::escape_path_separators(stats::hexdumpValue<BYTE>(&mVal, sizeof(BYTE)));
				}
				outs << "\"";
			}
			outs << ",\n";
			OUT_PADDED(outs, level, "\"entropy\" : ");
			outs << std::dec << entropy;
		}

		void summarize()
		{
			entropy = stats::calcShannonEntropy(histogram, size);
			finishLastStr(true);

			for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
				const size_t count = itr->second;
				const  BYTE val = itr->first;
				frequencies[count].insert(val);
			}
		}

		double entropy;
		size_t size;
		size_t offset;

		BYTE prevVal;
		size_t longestStr; // the longest ASCII string in the chunk

		std::string lastStr;
		size_t stringsCount;
		size_t cleanStringsCount;
		std::map<BYTE, size_t> histogram;
		std::map<size_t, std::set<BYTE>>  frequencies;

		MultiStatsSettings *settings;

		std::map<std::string, size_t> foundStrings;
#ifdef _KEEP_STR
		std::vector< std::string > allStrings;
#endif
	};

	class AreaMultiStats : public AreaStats {
	public:
		AreaMultiStats()
		{
		}

		// Copy constructor
		AreaMultiStats(const AreaMultiStats& p1)
			: currArea(p1.currArea)
		{
		}

		bool fillSettings(StatsSettings* settings)
		{
			MultiStatsSettings* multiSettings = dynamic_cast<MultiStatsSettings*>(settings);
			if (!multiSettings) return false;

			currArea.fillSettings(multiSettings);
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
		
		ChunkStats currArea; // stats from the whole area

	protected:
		void _appendVal(BYTE val)
		{
			currArea.appendVal(val);
		}

	};
};
