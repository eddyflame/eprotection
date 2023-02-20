#include <string>
#include <iostream>

#include "popl.hpp"
#include "encrypto_service.h"

using namespace eprot;
using namespace std;

int main(int argc, char** argv) {
	// parse cmd
    popl::OptionParser op("fhe data");
    auto help_op   = op.add<popl::Switch>("h", "help", "show this help message");
	auto usr_op    = op.add<popl::Value<string>>("u", "user", "user name");
    auto pass_op   = op.add<popl::Value<string>>("p", "password", "user password");

    try {
        op.parse(argc, argv);
        if (help_op->is_set()) {
            cout << op << endl;
            return 0;
        }

		if (!usr_op->is_set() or !pass_op->is_set()) {
			cout << op << endl;
			return 1;
		}

    } catch (const popl::invalid_option& e) {
        cout << e.what() << endl;
        cout << op << endl;
        return -1;
    }

	string usr = usr_op->value();
	string pass = pass_op->value();

	EncryptoService svc;
	auto result = svc.Calculate(usr, pass);
	cout<< "********************************" << endl;
	cout<< "     usr: " << usr << endl;
	cout<< "password: " << pass << endl;
	cout<< "  result: " << result << endl;
	cout<< "********************************" << endl;
	return 0;
}
