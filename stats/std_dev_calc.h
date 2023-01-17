#pragma once

#include <windows.h>
#include <iostream>
#include <map>

class StdDeviationCalc
{
private:

    size_t max;
    std::map<BYTE, size_t> &population;
    double mean;

public:
    StdDeviationCalc(std::map<BYTE, size_t>& _population, size_t _max)
        : mean(0), population(_population)
    {
        max = _max;
        mean = calcMean();
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

    double calcVariance()
    {
        if (max == 0) return 0;

        double temp = 0;
        for (auto itr = population.begin(); itr != population.end(); ++itr)
        {
            const double val = itr->second;
            temp += (val - mean) * (val - mean);
        }
        return temp / max;
    }

    double calcSampleVariance()
    {
        if ((max - 1) == 0) return 0;

        double temp = 0;
        for (auto itr = population.begin(); itr != population.end(); ++itr)
        {
            const double val = itr->second;
            temp += (val - mean) * (val - mean);
        }
        return temp / ((ULONG)max - 1);
    }

    double GetStandardDeviation()
    {
        return sqrt(calcVariance());
    }

    double calcSampleStandardDeviation()
    {
        return sqrt(calcSampleVariance());
    }

    void printAll()
    {
        std::cout << "Counts Sum:\t\t\t: " << calcSum() << "\n";
        std::cout << "Total Numbers\t\t\t: " << max << "\n";
        std::cout << "Mean\t\t\t\t: " << mean << "\n";
        std::cout << "Population Variance\t\t: " << calcVariance() <<"\n";
        std::cout << "Sample variance\t\t\t: " << calcSampleVariance() << "\n";
        std::cout << "Population Standard Deviation\t: " << GetStandardDeviation() << "\n";
        std::cout << "Sample Standard Deviation\t: " << calcSampleStandardDeviation() << "\n";
    }
};

