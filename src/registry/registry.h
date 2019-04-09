
#include <string>
#include <unordered_map>
#include <memory>


class registry_entry {
	std::string name;

};

class registry_class {
	
	public:
		registry_class(const std::string &name);

	protected:
		std::string name_;
		std::unordered_map<std::string, std::unique_ptr<registry_entry>> entries;
};

class registry {

	public:
		void add_class(const std::string &name);

	protected:
		std::unordered_map<std::string, std::unique_ptr<registry_class>> classes_;

};


