#pragma once

#include "apsi/item.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/oprf/oprf_receiver.h"

namespace eprot {

class EncryptoService {
public:
	EncryptoService() = default;
	std::string Calculate(const std::string& usr, const std::string pass);

private:
	apsi::oprf::OPRFKey GetKey(const std::string& usr);
	apsi::oprf::OPRFKey LoadKey(const std::string & pathname);
	int SaveKey(const apsi::oprf::OPRFKey & oprf_key, const std::string & pathname);

	std::pair<std::vector<apsi::HashedItem>, std::vector<apsi::LabelKey>> ExtractHashes(const std::vector<unsigned char>& oprf_datas, const apsi::oprf::OPRFReceiver &oprf_receiver);

};

}
