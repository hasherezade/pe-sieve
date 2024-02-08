#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>

#define MASK_IMM 0xFF
#define MASK_PARTIAL1 0x0F
#define MASK_PARTIAL2 0xF0
#define MASK_WILDCARD 0

namespace pattern_tree {

	class Signature
	{
	public:
		Signature(std::string _name, const BYTE* _pattern, size_t _pattern_size, const BYTE* _mask)
			: name(_name), pattern(nullptr), pattern_size(0), mask(nullptr)
		{
			this->pattern = (BYTE*)::calloc(_pattern_size, 1);
			if (!this->pattern) return;

			::memcpy(this->pattern, _pattern, _pattern_size);
			this->pattern_size = _pattern_size;

			if (_mask) {
				this->mask = (BYTE*)::calloc(_pattern_size, 1);
				if (this->mask) {
					::memcpy(this->mask, _mask, _pattern_size);
				}
			}
		}

		Signature(const Signature& _sign) // copy constructor
			: pattern(nullptr), pattern_size(0), mask(nullptr)
		{
			init(_sign.name, _sign.pattern, _sign.pattern_size, _sign.mask);
		}

		size_t size()
		{
			return pattern_size;
		}

		std::string name;

	protected:

		size_t pattern_size;
		BYTE* pattern;
		BYTE* mask;

	private:
		bool init(std::string _name, const BYTE* _pattern, size_t _pattern_size, const BYTE* _mask)
		{
			if (this->pattern || this->mask) return false;

			this->pattern = (BYTE*)::calloc(_pattern_size, 1);
			if (!this->pattern) return false;

			::memcpy(this->pattern, _pattern, _pattern_size);
			this->pattern_size = _pattern_size;

			if (_mask) {
				this->mask = (BYTE*)::calloc(_pattern_size, 1);
				if (this->mask) {
					::memcpy(this->mask, _mask, _pattern_size);
				}
			}
			return true;
		}

		friend class Node;
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
		static bool addPattern(Node* rootN, const char* _name, const BYTE* pattern, size_t pattern_size, const BYTE* pattern_mask=nullptr)
		{
			if (!rootN || !pattern || !pattern_size) {
				return false;
			}
			Node* next = rootN;
			for (size_t i = 0; i < pattern_size; i++) {
				BYTE mask = (pattern_mask != nullptr) ? pattern_mask[i] : MASK_IMM;
				next = next->addNext(pattern[i], mask);
				if (!next) return false;
			}
			next->sign = new Signature(_name, pattern, pattern_size, pattern_mask);
			return true;
		}

		static bool addTextPattern(Node* rootN, const char* pattern1)
		{
			return Node::addPattern(rootN, pattern1, (const BYTE*)pattern1, strlen(pattern1));
		}

		static bool addSignature(Node* rootN, const Signature& sign)
		{
			return addPattern(rootN, sign.name.c_str(), sign.pattern, sign.pattern_size, sign.mask);
		}

		//---

		Node()
			: level(0), val(0), mask(MASK_IMM),
			sign(nullptr)
		{
		}

		Node(BYTE _val, size_t _level, BYTE _mask)
			: val(_val), level(_level), mask(_mask),
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

		Node* getNode(BYTE _val, BYTE _mask)
		{
			BYTE maskedVal = _val & _mask;
			if (_mask == MASK_IMM) {
				return _findInChildren(immediates, maskedVal);
			}
			else if (_mask == MASK_PARTIAL1 || _mask == MASK_PARTIAL2) {
				return _findInChildren(partials, maskedVal);
			}
			else if (_mask == MASK_WILDCARD) {
				return _findInChildren(wildcards, maskedVal);
			}
			return nullptr;
		}

		Node* addNext(BYTE _val, BYTE _mask)
		{
			Node* nextN = getNode(_val, _mask);
			if (nextN) {
				return nextN;
			}

			BYTE maskedVal = _val & _mask;
			nextN = new Node(_val, this->level + 1, _mask);
			if (_mask == MASK_IMM) {
				immediates[maskedVal] = nextN;
			}
			else if (_mask == MASK_PARTIAL1 || _mask == MASK_PARTIAL2) {
				partials[maskedVal] = nextN;
			}
			else if (_mask == MASK_WILDCARD) {
				wildcards[maskedVal] = nextN;
			}
			else {
				delete nextN;
				std::cout << "Invalid mask supplied for value: " << std::hex << (unsigned int)_val << " Mask:" << (unsigned int)_mask << "\n";
				return nullptr; // invalid mask
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
					Node* curr = level1_ptr->at(k);
					if (curr->isSign()) {
						size_t match_start = i - curr->sign->size();
						Match m(match_start, curr->sign);
						matches.push_back(m);
						if (stopOnFirst) {
							return match_start;
						}
					}
					_followAllMasked(level2_ptr, curr, data[i]);
#ifdef SEARCH_BACK
					if (curr != this) {
						// the current value may also be a beginning of a new pattern:
						_followAllMasked(level2_ptr, this, data[i]);
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
			return (!immediates.size() && !partials.size() && !wildcards.size()) ? true : false;
		}

		bool isSign()
		{
			return sign ? true : false;
		}

	protected:
		Node* _findInChildren(std::map<BYTE, Node*>& children, BYTE _val)
		{
			auto found = children.find(_val);
			if (found != children.end()) {
				return found->second;
			}
			return nullptr;
		}

		bool _followMasked(ShortList<Node*>* level2_ptr, Node* curr, BYTE val, BYTE mask)
		{
			Node* next = curr->getNode(val, mask);
			if (!next) {
				return false;
			}
			return level2_ptr->push_back(next);
		}

		void _followAllMasked(ShortList<Node*>* level2_ptr, Node* node, BYTE val)
		{
			_followMasked(level2_ptr, node, val, MASK_IMM);
			_followMasked(level2_ptr, node, val, MASK_PARTIAL1);
			_followMasked(level2_ptr, node, val, MASK_PARTIAL2);
			_followMasked(level2_ptr, node, val, MASK_WILDCARD);
		}

		Signature* sign;
		BYTE val;
		BYTE mask;
		size_t level;
		std::map<BYTE, Node*> immediates;
		std::map<BYTE, Node*> partials;
		std::map<BYTE, Node*> wildcards;
	};

	inline size_t find_all_matches(Node& rootN, const BYTE* loadedData, size_t loadedSize, std::vector<Match>& allMatches)
	{
		if (!loadedData || !loadedSize) {
			return 0;
		}
		rootN.getMatching(loadedData, loadedSize, allMatches, false);
		return allMatches.size();
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
