#ifndef __PTYPE_H__
#define __PTYPE_H__

#include <string>
#include <stdexcept>
#include <iostream>

#include "pkt/pkt_buffer.h"

class ptype {

	public:

		ptype(const std::string& name) : type_name_(name) {};
		virtual bool parse(const std::string& val) = 0;
		virtual const std::string print() const = 0;

		const std::string& get_type() const { return type_name_; };
		virtual void set_value(pkt_buffer *pkt, std::size_t offset) { throw std::runtime_error("This ptype cannot read value from pkt_buffer");};

		friend std::ostream& operator<<(std::ostream &os, const ptype &p) {
			os << p.print();
			return os;
		};

	protected:
		const std::string type_name_;

};


#endif
