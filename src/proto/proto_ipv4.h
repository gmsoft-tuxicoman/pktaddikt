#ifndef __PROTO_IPV4_H__
#define __PROTO_IPV4_H__

#include "proto.h"
#include "conntrack.h"

#include "ptype/ptype_ipv4.h"
#include "ptype/ptype_uint8.h"

using conntrack_ipv4_key = std::tuple<ptype_ipv4, ptype_ipv4, ptype_uint8>;
using conntrack_ipv4_table = conntrack_table_multi<conntrack_ipv4_key>;

namespace std {

	template <> struct hash<conntrack_ipv4_key> {
		std::size_t operator() (conntrack_ipv4_key const &k) const noexcept {
			uint32_t first = std::get<0>(k).get_ip().s_addr;
			uint32_t second = std::get<1>(k).get_ip().s_addr;
			uint8_t id = std::get<2>(k).get_value();

			if (first < second) {
				uint32_t tmp = first;
				first = second;
				second = tmp;
			}

			first ^= (uint32_t)id << 24;

			if (sizeof(std::size_t) >= 8) {
				return (std::size_t) (first << (8 * sizeof(uint32_t)) + second);
			} else {
				assert(sizeof(std::size_t) >= 4);
				return first ^ bswap_32(second);
			}
		}
	};

	template <> struct equal_to<conntrack_ipv4_key> {
		bool operator() (const conntrack_ipv4_key &lhs, const conntrack_ipv4_key &rhs) const {
			uint8_t lid = std::get<2>(lhs).get_value();
			uint8_t rid = std::get<2>(rhs).get_value();

			if (lid != rid)
				return false;

			uint32_t lfirst = std::get<0>(lhs).get_ip().s_addr;
			uint32_t rfirst = std::get<0>(rhs).get_ip().s_addr;
			uint32_t lsecond = std::get<1>(lhs).get_ip().s_addr;
			uint32_t rsecond = std::get<1>(rhs).get_ip().s_addr;

			return ((lfirst == rfirst && lsecond == rsecond) || (lfirst == rsecond && lsecond == rfirst));
		}
	};


}

class proto_ipv4 : public proto {

	public:
		static void register_number();

		proto_ipv4(pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor): proto(pkt, parse_flag_pre | parse_flag_fetch, parent,  executor) {};

		static proto* factory(pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor) { return new proto_ipv4(pkt, parent, executor); };

		void parse_pre_session() override;
		void parse_fetch_session(pa_task fetch_session_done) override;
		void parse_in_session() override;
		
		enum fields_id { src, dst, protocol, tos, ttl };

		static conntrack_table_ptr conntrack_table_factory(task_executor_ptr executor) { return std::make_shared<conntrack_ipv4_table>(executor); } override;

	protected:

		ptype_ipv4 field_src_;
		ptype_ipv4 field_dst_;
		ptype_uint8 field_proto_;
		ptype_uint8 field_tos_;
		ptype_uint8 field_ttl_;

		proto_fields fields_ = {
			{ "src", &field_src_ },
			{ "dst", &field_dst_ },
			{ "proto", &field_proto_ },
			{ "tos", &field_tos_ },
			{ "ttl", &field_ttl_ } };


};


#endif
