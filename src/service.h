#pragma once

namespace eprot {

class Service {
public:

	void calculate(const std::string& usr, const std::string pass);

private:
	void createKey(const std::string& usr);


};

}
