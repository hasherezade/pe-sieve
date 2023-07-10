#pragma once

#include <windows.h>
#include <iostream>
#include <map>

namespace pesieve {
	namespace stats {

		class StdDeviationCalc
		{
		public:
			StdDeviationCalc(const std::map<BYTE, size_t>& _population, size_t _max)
				: mean(0), population(_population)
			{
				max = _max;
				mean = calcMean();
			}

			double getSum() { return sum; }

			double getMean() { return mean; }

			double calcSampleVariance()
			{
				if (max == 0) return 0;
				return _calcVariance(max - 1);
			}

			double calcPopulationVariance()
			{
				return _calcVariance(max);
			}
			
			double calcSampleStandardDeviation()
			{
				return sqrt(calcSampleVariance());
			}

			double calcPopulationStandardDeviation()
			{
				return sqrt(calcPopulationVariance());
			}
			
			void printAll()
			{
				std::cout << "Counts Sum:\t\t\t: " << calcSum() << "\n";
				std::cout << "Total Numbers\t\t\t: " << max << "\n";
				std::cout << "Mean\t\t\t\t: " << mean << "\n";
				std::cout << "Population Variance\t\t: " << calcPopulationVariance() << "\n";
				std::cout << "Sample variance\t\t\t: " << calcSampleVariance() << "\n";
				std::cout << "Population Standard Deviation\t: " << calcPopulationStandardDeviation() << "\n";
				std::cout << "Sample Standard Deviation\t: " << calcSampleStandardDeviation() << "\n";
			}

		private:

			double _calcVariance(ULONG _max)
			{
				if (_max == 0) return 0;

				double temp = 0;
				for (auto itr = population.begin(); itr != population.end(); ++itr)
				{
					const double val = itr->second;
					temp += (val - mean) * (val - mean);
				}
				return temp / _max;
			}

			double calcSum()
			{
				double sum = 0;
				for (auto itr = population.begin(); itr != population.end(); ++itr) {
					const double val = itr->second;
					sum += val;
				}
				return sum;
			}

			double calcMean()
			{
				if (max == 0) return 0;

				double sum = calcSum();
				return (sum / max);
			}

			size_t max;
			const std::map<BYTE, size_t>& population;
			double mean;
			double sum;

		}; // namespace stats
	}; // namespace pesieve
};
