#ifndef __PROTO_H__
#define __PROTO_H__

#include <vector>
#include <map>
#include "ptype/ptype.h"

class pkt;
class proto;

using proto_fields = std::vector<std::pair<std::string, ptype*>>;

class proto {

	public:
		~proto();

		virtual proto* factory(pkt *pkt) = 0;
		virtual void parse() = 0;

	protected:
		proto(pkt* pkt): pkt_(pkt) {};
		proto(std::string name): name_(name) {};

		std::string name_;
		pkt *pkt_;

		proto_fields fields_;

};

#endif