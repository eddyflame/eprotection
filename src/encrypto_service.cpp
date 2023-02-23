#include <string>
#include <fstream>
#include <filesystem>

#include "encrypto_service.h"
#include "apsi/item.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/util/utils.h"

using namespace eprot;
using namespace std;

std::string EncryptoService::Calculate(const std::string& usr, const std::string pass) {
	if (usr.empty() or pass.empty()) {
		cout<< "param error" << endl;
		throw runtime_error("param error");
	}

	// get oprf key by usr
	auto key = GetKey(usr);
	// cout<< "get key ok"<<endl;

	// str to item (hash) item is 16 byte array
	vector<apsi::Item> items;
	apsi::Item item(usr+pass);
	items.emplace_back(item);

	// receiver oprf,
	// cout<< "receiver oprf"<<endl;
	apsi::oprf::OPRFReceiver recv(items);
	auto cipher = recv.query_data();

	// run oprf
	// cout<< "run oprf"<<endl;
	auto oprf_data = apsi::oprf::OPRFSender::ProcessQueries(cipher, key);

	// get result
	// cout<< "get oprf"<<endl;
	auto [hashed_items, label_keys] = ExtractHashes(oprf_data, recv);
	if (hashed_items.size() == 0) {
		cout<< "extract hashes error"<<endl;
		throw runtime_error("extract hasheds error");
	}

	cout<< "result : " << hashed_items.at(0).to_string() <<endl;
	// return new password (hashed string)
	return hashed_items.at(0).to_string();
}


apsi::oprf::OPRFKey EncryptoService::GetKey(const std::string& usr) {
	string path(usr + ".key");
	if (std::filesystem::exists(path)) {
		cout<< "find key file: " << path << endl;
		return move(LoadKey(path));
	}

	cout<< "can not find key file: " << path << endl;

	apsi::oprf::OPRFKey key;
	cout<< "create oprf key" << endl;
	SaveKey(key, path);
	cout<< "save key ok" << endl;
	return key;
}

apsi::oprf::OPRFKey EncryptoService::LoadKey(const string & pathname) {
	auto fsize = std::filesystem::file_size(pathname);
    if (0 == fsize) {
        cout<< "key file empty: "<< pathname << endl;
		throw std::runtime_error(std::string("key file empty: ") + pathname);
    }

	ifstream in(pathname, ios::binary);
	if (!in.is_open()) {
		cout<<"open file error: " << pathname << endl;
		throw std::runtime_error(std::string("open file error: ") + pathname);
	}

	apsi::oprf::OPRFKey oprf_key;
	oprf_key.load(in);
	return oprf_key;
}

int EncryptoService::SaveKey(const apsi::oprf::OPRFKey & oprf_key, const string & pathname) {
    cout<< "save oprf key ready!" << endl;

    ofstream out(pathname, ios::trunc|ios::binary);
    if (!out.is_open()) {
        cout<< "open file error: " << pathname << endl;
        return -1;
    }

    oprf_key.save(out);
    cout<< "save oprf key ok!" << endl;
    return 0;
}

pair<vector<apsi::HashedItem>, vector<apsi::LabelKey>> EncryptoService::ExtractHashes(const vector<unsigned char>& oprf_datas, const apsi::oprf::OPRFReceiver &oprf_receiver) {

    auto size = oprf_datas.size();
    size_t oprf_response_item_count = size / apsi::oprf::oprf_response_size;
    if ((size % apsi::oprf::oprf_response_size) ||
        (oprf_response_item_count != oprf_receiver.item_count())) {
        cout<< "Failed to extract OPRF hashes for items: unexpected OPRF response (size "<< size << " B)";
        return {};
    }

    vector<apsi::HashedItem> items(oprf_receiver.item_count());
    vector<apsi::LabelKey> label_keys(oprf_receiver.item_count());
    oprf_receiver.process_responses(oprf_datas, items, label_keys);
    cout<< "Extracted OPRF hashes for " << oprf_response_item_count << " items";
    return {move(items), move(label_keys)};
}