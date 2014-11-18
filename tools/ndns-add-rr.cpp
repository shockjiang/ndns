/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014, Regents of the University of California.
 *
 * This file is part of NDNS (Named Data Networking Domain Name Service).
 * See AUTHORS.md for complete list of NDNS authors and contributors.
 *
 * NDNS is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NDNS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NDNS, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mgmt/management-tool.hpp"
#include "ndns-label.hpp"
#include "logger.hpp"
#include "util/util.hpp"

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <string>

int
main(int argc, char * argv[])
{
  using std::string;
  using namespace ndn;
  using namespace ndns;

  ndn::ndns::log::init();
  int ttlInt = -1;
  int versionInt = -1;
  string zoneStr;
  string dskStr;
  string db;
  string rrLabelStr;
  string rrTypeStr;
  string ndnsTypeStr;
  string contentStr;
  try {
    namespace po = boost::program_options;
    po::variables_map vm;

    po::options_description generic("Generic Options");
    generic.add_options()("help,h", "print help message");

    po::options_description config("Configuration");
    config.add_options()
      ("ndnsType", po::value<string>(&ndnsTypeStr), "Set the ndnsType of the resource record."
        "Default: resp for NS and TXT, raw for unknown RR type")
      ("dsk,d", po::value<std::string>(&dskStr), "Set the name of DSK's certificate. "
        "Default: use default DSK and its default certificate")
      ("content,c", po::value<string>(&contentStr), "Set the content of resource record. "
        "Default: null string")
      ("ttl,a", po::value<int>(&ttlInt), "Set ttl of the rrset. Default: 3600 seconds")
      ("version,v", po::value<int>(&ttlInt), "Set version of the rrset. Default: Unix Timestamp")
      ("db,b", po::value<std::string>(&db), "Set the path of NDNS server database. "
        "Default: " DEFAULT_DATABASE_PATH "/ndns.db")
      ;

    po::options_description hidden("Hidden Options");
    hidden.add_options()
      ("zone", po::value<string>(&zoneStr), "host zone name")
      ("label", po::value<string>(&rrLabelStr), "label of resource record.")
      ("type", po::value<string>(&rrTypeStr), "Set the type of resource record.")
      ;

    po::positional_options_description postion;
    postion.add("zone", 1);
    postion.add("label", 1);
    postion.add("type", 1);
    postion.add("ndnsType", 1);

    po::options_description cmdline_options;
    cmdline_options.add(generic).add(config).add(hidden);

    po::options_description config_file_options;
    config_file_options.add(config).add(hidden);

    po::options_description visible("Allowed options");
    visible.add(generic).add(config);

    po::parsed_options parsed =
      po::command_line_parser(argc, argv).options(cmdline_options).positional(postion).run();

    po::store(parsed, vm);
    po::notify(vm);


    if (vm.count("help")) {
      std::cout << "Usage: ndns-add-rr zone label [NS|ID-CERT|TXT|*] [-n resp|nack|auth|raw] "
        "[-d dskCert] [-c content] [-a ttl] [-v version] [-b db]" << std::endl;
      std::cout << visible << std::endl;
      return 0;
    }

    if (vm.count("zone") == 0) {
      std::cerr << "zone must be specified" << std::endl;
      return 1;
    }

    if (vm.count("label") == 0) {
      std::cerr << "label must be specified" << std::endl;
      return 1;
    }

    if (vm.count("type") == 0) {
      std::cerr << "type must be specified" << std::endl;
      return 1;
    }
  }
  catch (const std::exception& ex) {
    std::cerr << "Parameter Error: " << ex.what() << std::endl;
    return 1;
  }

  try {
    Name zoneName(zoneStr);
    Name label(rrLabelStr);
    name::Component type(rrTypeStr);

    if (ndnsTypeStr.empty()) {
      if (rrTypeStr == "NS" || rrTypeStr == "TXT")
        ndnsTypeStr = "resp";
      else
        ndnsTypeStr = "raw";
    }
    NdnsType ndnsType = ndns::toNdnsType(ndnsTypeStr);
    Name dskName(dskStr);
    time::seconds ttl;
    if (ttlInt == -1)
      ttl = ndns::DEFAULT_CACHE_TTL;
    uint64_t version = static_cast<uint64_t>(versionInt);

    ndn::ndns::ManagementTool tool(db);
    tool.addRrSet(zoneName, label, type, ndnsType, version, contentStr, dskName, ttl);
  }
  catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << std::endl;
    return 1;
  }
}
