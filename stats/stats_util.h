#pragma once

#include <windows.h>
#include <iostream>
#include <string>

namespace pesieve {
	namespace stats {

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
		T getMostFrequentValue(IN std::map<size_t, std::set< T >> frequencies)
		{
			auto itr = frequencies.rbegin();
			if (itr == frequencies.rend()) {
				return 0;
			}
			auto setItr = itr->second.begin();
			T mVal = *setItr;
			return mVal;
		}

		// return the number of occurrencies
		template <typename T>
		size_t getMostFrequentValues(IN std::map<size_t, std::set< T >> frequencies, OUT std::set<T>& values)
		{
			auto itr = frequencies.rbegin();
			if (itr == frequencies.rend()) {
				return 0;
			}

			// find the highest frequency:
			size_t mFreq = itr->first;
			values.insert(itr->second.begin(), itr->second.end());
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

	}; // namespace stats
}; //namespace pesieve
