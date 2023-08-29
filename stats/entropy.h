#pragma once

#include <cmath>
#include <map>
namespace pesieve {

	namespace stats {

		template <typename T> size_t generateHistogram(IN T buffer[], IN size_t bufferSize, OUT std::map<T, size_t> &counts)
		{
			if (!buffer || !bufferSize) return 0;

			for (size_t i = 0; i < bufferSize; ++i) {
				const T val = buffer[i];
				counts[val]++;
			}
			return counts.size();
		}

		// Shannon's Entropy calculation based on: https://stackoverflow.com/questions/20965960/shannon-entropy
		template <typename T>
		double calcShannonEntropy(std::map<T, size_t>& histogram, size_t totalSize)
		{
			if (!totalSize) return 0;
			double entropy = 0;
			for (auto it = histogram.begin(); it != histogram.end(); ++it) {
				double p_x = (double)it->second / totalSize;
				if (p_x > 0) entropy -= p_x * log(p_x) / log((double)2);
			}
			return entropy;
		}

		template <typename T> static double ShannonEntropy(T buffer[], size_t bufferSize)
		{
			std::map<T, size_t> counts;
			if (!generateHistogram<T>(buffer, bufferSize, counts)) {
				return 0;
			}
			return calcShannonEntropy<T>(counts, bufferSize);
		}

	}; // namespace stats

}; //namespace pesieve

