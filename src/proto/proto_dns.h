#ifndef __PROTO_DNS_H__
#define __PROTO_DNS_H__


class proto_dns : public proto {

	public:
		static void register_number();
		static proto* factory(pkt *pkt, task_executor_ptr executor) { return new proto_dns(pkt, executor); };

		proto_dns(pkt *pkt, task_executor_ptr executor): proto(pkt, parse_flag_fetch, executor), {};

		void parse_pre_session() {};
		void parse_fetch_session(pa_task fetch_session_done) { this->fetch_session(fetch_session_done); };
		void parse_in_session() {};

		enum fields_id { id, response, rcode, qdcount, ancount, nscount, arcount };

	protected:

		ptype_uint16 field_id_;
		ptype_bool field_response_;
		ptype_uint8 field_rcode_;
		ptype_uint16 field_qdcount_;
		ptype_uint16 field_ancount_;
		ptype_uint16 field_nscount_;
		ptype_uint16 field_arcount_;

		proto_fields fields_ {
			{ "id", &field_id_ },
			{ "response", &field_response_ },
			{ "qdcount", &field_qdcount_ },
			{ "ancount", &field_ancount_ },
			{ "nscount", &field_nscount_ },
			{ "arcount_", &field_arcount_ }};

};


#endif

