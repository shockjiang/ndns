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

#include "logger.hpp"
#include "clients/response.hpp"
#include "validator.hpp"
#include "util/util.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>

#include <algorithm>

namespace ndn {
namespace ndns {
NDNS_LOG_INIT("NdnsShot")

class NdnsShot : noncopyable
{
public:
  NdnsShot(const Name interestName, Face& face, Validator& validator)
    : m_interestName(interestName)
    , m_face(face)
    , m_validator(validator)
    , m_hasError(false)
  {
  }

public:
  bool
  hasError() const
  {
    return m_hasError;
  }

  void
  run()
  {
    NDNS_LOG_INFO("plan to requested data from zone: " << m_zone);
    Interest interest = this->toInterest();
    NDNS_LOG_INFO("[* <- *] express Interest: " << interest.getName());
    m_face.expressInterest(interest,
                           boost::bind (&NdnsShot::onData, this, _1, _2),
                           // dynamic binding, if onData is override, bind to the new function
                           boost::bind (&NdnsShot::onTimeout, this, _1) //dynamic binding
                           );

    try {
      m_face.processEvents();
    }
    catch (std::exception& e) {
      NDNS_LOG_WARN("Face fails to process events: " << e.what());
    }
  }

private:
  void
  onData(const Interest& interest, const Data& data)
  {
    NDNS_LOG_INFO("Zone= "<< m_zone << " returns Data " << data.getName());
    Response response;

    try {
      response.fromData("", m_zone, data);
    }
    catch (std::exception& e) {
      NDNS_LOG_INFO("cannot parse Data to Response");
      NDNS_LOG_INFO("data: " << data);
    }

    NDNS_LOG_INFO(response);
    NDNS_LOG_INFO("This is the final response returned by zone=" << response.getZone()
                  << " and NdnsType=" << response.getNdnsType()
                  << ". It contains " << response.getRrs().size() << " RR(s)");

    NDNS_LOG_WARN("---------* GET A " << response.getNdnsType() <<" *---------");

    std::string msg;
    size_t i = 1;
    for (const auto& rr : response.getRrs()) {
      try {
        msg =  std::string(reinterpret_cast<const char*>(rr.value()), rr.value_size());
        NDNS_LOG_INFO("succeed to get the info from the " << i << "th RR: "
                      "type=" << rr.type() << " content=" << msg);
      }
      catch (std::exception& e) {
        NDNS_LOG_INFO("error to get the info from the " << i << "th RR"
                      "type=" << rr.type());
      }
      i += 1;
    }

    if (m_dstFile.empty()) {
      ;
    }
    else if (m_dstFile == "-") {
      output(data, std::cout, true);
    }

    else {
      std::string tmp = m_dstFile;
      if (m_dstFile.at(m_dstFile.size() - 1) == '/') { // m_dstFile is an dir
        tmp = data.getName().toUri();
        std::replace(tmp.begin(), tmp.end(), '/', '.');
        tmp = tmp.substr(1);
        tmp = m_dstFile + tmp;
      }

      NDNS_LOG_INFO("output Data packet to " << tmp << " with BASE64 encoding format");
      std::filebuf fb;
      fb.open (tmp,std::ios::out);
      std::ostream os(&fb);
      output(data, os, false);
    }

    NDNS_LOG_TRACE("to verify the data");
    m_validator.validate(data,
                         bind(&NdnsShot::onDataValidated, this, _1),
                         bind(&NdnsShot::onDataValidationFailed, this, _1, _2)
                         );
  }


  void
  onTimeout(const ndn::Interest& interest)
  {

    NDNS_LOG_INFO( "[* !! *] Interest: " << interest.getName()
                   <<" cannot fetch data");
    this->stop();
  }


  void
  onDataValidated(const shared_ptr<const Data>& data)
  {
    NDNS_LOG_INFO("final data pass verification");
    this->stop();
  }

  void
  onDataValidationFailed(const shared_ptr<const Data>& data, const std::string& str)
  {
    NDNS_LOG_INFO("final data does not pass verification");
    m_hasError = true;
    this->stop();
  }

  Interest
  toInterest()
  {
    Interest interest(m_interestName);
    interest.setInterestLifetime(this->m_interestLifetime);
    return interest;
  }

  void
  stop()
  {
    m_face.getIoService().stop();
    NDNS_LOG_INFO("application stops.");
  }

public:
  void
  setInterestLifetime(const time::milliseconds& lifetime)
  {
    m_interestLifetime = lifetime;
  }

  void
  setZone(const Name name)
  {
    m_zone = name;
  }

  void
  setDstFile(const std::string& dstFile)
  {
    m_dstFile = dstFile;
  }

private:
  Name m_interestName;
  time::milliseconds m_interestLifetime;
  Name m_zone;
  Face& m_face;
  Validator& m_validator;
  bool m_hasError;
  std::string m_dstFile;
}; // class NdnsShot

} // namespace ndns
} // namespace ndn


int main(int argc, char* argv[])
{
  using std::string;
  using namespace ndn;
  using namespace ndn::ndns;
  std::vector<Name> names;
  ndn::ndns::log::init();
  string dstFile;
  string validatorFile = ndns::Validator::VALIDATOR_CONF_FILE;
  int ttl = 4;

  try {
    namespace po = boost::program_options;
    po::variables_map vm;

    po::options_description generic("Generic Options");
    generic.add_options()("help,h", "print help message");

    po::options_description config("Configuration");
    config.add_options()
      ("timeout,T", po::value<int>(&ttl), "waiting seconds of query. default: 4 sec")
      ("dstFile,d", po::value<std::string>(&dstFile), "set output file of the received Data. "
       "if not set (default), not print; if set to be -, print to stdout; else print to file")
      ("validator,v", po::value<std::string>(&validatorFile), "set the validator configuration file"
      )
      ;

    po::options_description hidden("Hidden Options");
    hidden.add_options()
      ("names", po::value<std::vector<Name>>(&names), "names to be fetched")
      ;
    po::positional_options_description postion;
    postion.add("names", -1);

    po::options_description cmdline_options;
    cmdline_options.add(generic).add(config).add(hidden);

    po::options_description config_file_options;
    config_file_options.add(config).add(hidden);

    po::options_description visible("Usage: ndns-shot /name/without-version [-T ttl] [-d dstFile]\n"
                                    "Allowed options");
    visible.add(generic).add(config);

    po::parsed_options parsed =
      po::command_line_parser(argc, argv).options(cmdline_options).positional(postion).run();

    po::store(parsed, vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cout << visible << std::endl;
      return 1;
    }

    if (!vm.count("names")) {
      std::cerr <<"no target name is input" << std::endl;
      return 1;
    }
  }
  catch (const std::exception& ex) {
    std::cerr << "Parameter Error: " << ex.what() << std::endl;
    return 1;
  }

  Face face;
  try {
    ndns::Validator validator(face, validatorFile);

    for (const Name& name : names) {
      Name zone;
      shared_ptr<Regex> regex = make_shared<Regex>("(<>*)<KEY>(<>+)<ID-CERT><>*");
      shared_ptr<Regex> regex2 = make_shared<Regex>("(<>*)<NDNS>(<>+)");

      if (regex->match(name)) {
        zone = regex->expand("\\1");
      }
      else if (regex2->match(name)) {
        zone = regex2->expand("\\1");
      }
      else {
        std::cerr << "The name: " << name << " does not contains NDNS tag: "
                  << ndns::label::NDNS_CERT_QUERY
                  << " or " << ndns::label::NDNS_ITERATIVE_QUERY
                  << std::endl
                  << "Ingore name: " << name << std::endl;
        //continue;
      }

      NdnsShot shot(name, face, validator);
      shot.setZone(zone);
      shot.setInterestLifetime(ndn::time::milliseconds(ttl * 1000));
      shot.setDstFile(dstFile);
      shot.run();
      if (shot.hasError())
        return 1;
      else
        return 0;
      std::cout << (shot.hasError() ? "Fail" : "Succeed") << " to get Data of name " << name
                << std::endl;
    }
  }
  catch (const ndn::ValidatorConfig::Error& e) {
    std::cerr << "Fail to create the validator: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
