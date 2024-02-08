#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>

namespace pattern_tree {

	class Signature
	{
	public:
		Signature(std::string _name, const BYTE* _pattern, size_t _pattern_size)
			: name(_name), pattern(nullptr), pattern_size(0)
		{
			this->pattern = (BYTE*)::calloc(_pattern_size, 1);
			if (!this->pattern) return;

			::memcpy(this->pattern, _pattern, _pattern_size);
			this->pattern_size = _pattern_size;
		}

		size_t size()
		{
			return pattern_size;
		}

		std::string name;

	protected:
		size_t pattern_size;
		BYTE* pattern;
	};

	class Match
	{
	public:
		Match()
			: offset(0), sign(nullptr)
		{
		}

		Match(size_t _offset, Signature* _sign)
			: offset(_offset), sign(_sign)
		{
		}

		Match(const Match& _match) // copy constructor
		{
			offset = _match.offset;
			sign = _match.sign;
		}

		size_t offset;
		Signature* sign;
	};

	template<class Element> class ShortList
	{
	public:
		ShortList()
			: elCount(0)
		{
		}

		bool push_back(Element n)
		{
			if (elCount >= _countof(list)) {
				return false;
			}
			if (find(n)) {
				return true;
			}
			list[elCount] = n;
			elCount++;
			return true;
		}

		Element at(size_t i)
		{
			if (i < _countof(list)) {
				return list[i];
			}
			return nullptr;
		}

		Element find(Element& searched)
		{
			for (size_t i = 0; i < elCount; i++) {
				if (list[i] == searched) {
					return list[i];
				}
			}
			return nullptr;
		}

		void clear()
		{
			elCount = 0;
		}

		size_t size()
		{
			return elCount;
		}

	protected:
		size_t elCount;
		Element list[100];
	};

	class Node
	{
	public:

		static bool addPattern(Node* rootN, const char* _name, const BYTE* pattern, size_t pattern_size)
		{
			if (!rootN || !pattern || !pattern_size) {
				return false;
			}
			Node* next = rootN;
			for (size_t i = 0; i < pattern_size; i++) {
				next = next->addNext(pattern[i]);
				if (!next) return false;
			}
			next->sign = new Signature(_name, pattern, pattern_size);
			return true;
		}

		static bool addTextPattern(Node* rootN, const char* pattern1)
		{
			return Node::addPattern(rootN, pattern1, (const BYTE*)pattern1, strlen(pattern1));
		}

		//---

		Node()
			: level(0), val(0),
			sign(nullptr)
		{
		}

		Node(BYTE _val, size_t _level)
			: val(_val), level(_level),
			sign(nullptr)
		{
		}

		~Node()
		{
			for (auto itr = immediates.begin(); itr != immediates.end(); ++itr) {
				Node* next = itr->second;
				delete next;
			}
			immediates.clear();
			if (sign) {
				delete sign;
			}
		}

		Node* getNode(BYTE _val)
		{
			auto found = immediates.find(_val);
			if (found != immediates.end()) {
				return found->second;
			}
			return nullptr;
		}

		Node* addNext(BYTE _val)
		{
			Node* nextN = getNode(_val);
			if (!nextN) {
				nextN = new Node(_val, this->level + 1);
				immediates[_val] = nextN;
			}
			return nextN;
		}

		void print()
		{
			std::cout << std::hex << (unsigned int)val << " [" << level << "]" << " [" << immediates.size() << "]";
			if (!immediates.size()) {
				printf("\n");
				return;
			}
			for (auto itr = immediates.begin(); itr != immediates.end(); ++itr) {
				itr->second->print();
			}
		}

#define SEARCH_BACK
		size_t getMatching(const BYTE* data, size_t data_size, std::vector<Match> &matches, bool stopOnFirst)
		{
			size_t processed = 0;
			//
			ShortList<Node*> level;
			level.push_back(this);
			ShortList<Node*> level2;

			auto level1_ptr = &level;
			auto level2_ptr = &level2;

			for (size_t i = 0; i < data_size; i++)
			{
				processed = i; // processed bytes
				level2_ptr->clear();
				for (size_t k = 0; k < level1_ptr->size(); k++) {
					Node * curr = level1_ptr->at(k);
					if (curr->isSign()) {
						size_t match_start = i - curr->sign->size();
						Match m(match_start, curr->sign);
						matches.push_back(m);
						if (stopOnFirst) {
							return match_start;
						}
					}
					Node* prev = curr;
					curr = prev->getNode(data[i]);
					if (curr) {
						level2_ptr->push_back(curr);
					}
#ifdef SEARCH_BACK
					if (prev != this) {
						// the current value may also be a beginning of a new pattern:
						Node* start = this->getNode(data[i]);
						if (start) {
							level2_ptr->push_back(start);
						}
					}
#endif
				}
				if (!level2_ptr->size()) {
#ifdef SEARCH_BACK
					// restart search from the beginning
					level2_ptr->push_back(this);
#else
					return results;
#endif //SEARCH_BACK
				}
				//swap:
				auto tmp = level1_ptr;
				level1_ptr = level2_ptr;
				level2_ptr = tmp;
			}
			return processed;
		}

		bool isEnd()
		{
			return this->immediates.size() ? false : true;
		}

		bool isSign()
		{
			return sign ? true : false;
		}

	protected:
		Signature* sign;
		BYTE val;
		size_t level;
		std::map<BYTE, Node*> immediates;
	};


	inline size_t find_all_matches(Node& rootN, const BYTE* loadedData, size_t loadedSize, std::vector<Match> &allMatches)
	{
		if (!loadedData || !loadedSize) {
			return 0;
		}
		size_t counter = 0;
		rootN.getMatching(loadedData, loadedSize, allMatches, false);
		if (allMatches.size()) {
			counter += allMatches.size();
		}
		return counter;
	}

	inline Match find_first_match(Node& rootN, const BYTE* loadedData, size_t loadedSize)
	{
		Match empty;
		if (!loadedData || !loadedSize) {
			return empty;
		}
		std::vector<Match> allMatches;
		rootN.getMatching(loadedData, loadedSize, allMatches, true);
		if (allMatches.size()) {
			auto itr = allMatches.begin();
			return *itr;
		}
		return empty;
	}

}; //namespace pattern_tree
