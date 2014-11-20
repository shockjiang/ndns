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

#include "ndns-label.hpp"
#include "logger.hpp"
#include "clients/response.hpp"
#include "clients/query.hpp"
#include "clients/iterative-query-controller.hpp"
#include "validator.hpp"
#include "daemon/rrset.hpp"
#include "daemon/db-mgr.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>

#include <memory>
#include <string>
#include <stdio.h>

namespace ndn {
namespace ndns {
NDNS_LOG_INIT("NdnsDemo");

static Zone EMPTY_ZONE("/");

class NdnsDemoData : noncopyable
{

public:
  NdnsDemoData(const Name& root, const std::string& certFile, const std::string configFile,
               const std::string& dbFile, const std::string& validatorFile)
    : m_root(root)
    , m_certDst(certFile)
    , m_configFile(configFile)
    , m_dbFile(dbFile)
    , m_validatorFile(validatorFile)
    , m_dbMgr(dbFile)
  {
  }

  void
  run()
  {
    m_dbMgr.clearAllData();
    m_ndn = Name(m_root).append("ndn");
    m_edu = Name(m_ndn).append("edu");
    m_ucla = Name(m_edu).append("ucla");
    m_alice = Name(m_ucla).append("alice");
    m_bob = Name(m_ucla).append("bob");

    m_rootZone = Zone(m_root);
    m_ndnZone = Zone(m_ndn);
    m_eduZone = Zone(m_edu);
    m_uclaZone = Zone(m_ucla);

    NDNS_LOG_DEBUG("delete existing identities");
    m_keyChain.deleteIdentity(m_root);
    m_keyChain.deleteIdentity(m_ndn);
    m_keyChain.deleteIdentity(m_edu);
    m_keyChain.deleteIdentity(m_ucla);
    m_keyChain.deleteIdentity(m_alice);
    m_keyChain.deleteIdentity(m_bob);

    NDNS_LOG_DEBUG("create root zone");
    Name tmp = createRoot(m_root); // replace to root cert
    tmp = createIdentity(m_ndn, tmp, m_rootZone, m_ndnZone);
    tmp = createIdentity(m_edu, tmp, m_ndnZone, m_eduZone);
    Name uclaCert = createIdentity(m_ucla, tmp, m_eduZone, m_uclaZone);

    tmp = createIdentity(m_alice, uclaCert, m_uclaZone, EMPTY_ZONE);
    this->addRr(m_uclaZone, tmp, "/alice", "TXT", NDNS_RESP);

    tmp = createIdentity(m_bob, uclaCert, m_uclaZone, EMPTY_ZONE);
    this->addRr(m_uclaZone, tmp, "/bob", "TXT", NDNS_RESP);
    // this->addRr(m_uclaZone, tmp, Name("/cs"), "NS", NDNS_AUTH);
    // this->addRr(m_uclaZone, tmp, "/cs/alex", "TXT", NDNS_RESP);
    // this->addRr(m_uclaZone, tmp, "/cs/shock", "TXT", NDNS_RESP);

    NDNS_LOG_DEBUG("replace NDNS Daemon Configuration file");
    this->saveNdnsConf();

    NDNS_LOG_DEBUG("replace Validator Configuration file");
    this->saveValidatorConf();

    NDNS_LOG_DEBUG("replace log4cxx Configuration file");
    this->saveLogConf();
  }

  void
  saveNdnsConf()
  {
    std::string str =
      "zones                                         \n"
      "{                                             \n"
      "  dbFile ";

    str += m_dbFile + "                        \n";

    str +=
      "                                              \n"
      "  zone {                                      \n"
      "    name /                                    \n"
      "  }                                           \n"
      "                                              \n"
      "  zone {                                      \n"
      "    name /ndn                                 \n"
      "  }                                           \n"
      "                                              \n"
      "  zone {                                      \n"
      "    name /ndn/edu                             \n"
      "  }                                           \n"
      "                                              \n"
      "  zone {                                      \n"
      "    name /ndn/edu/ucla                        \n"
      "  }                                           \n"
      "}                                             \n"
      "                                              \n"
      "hints                                         \n"
      "{                                             \n"
      "  hint /ucla                                  \n"
      "  hint /att                                   \n"
      "}                                             \n"
      ;

    std::ofstream os(m_configFile.c_str());
    os << str;
    os.close();
    NDNS_LOG_TRACE("FS: write NDNS daemon configuration to " << m_configFile);
  }

  void
  saveValidatorConf()
  {
    std::string str =
      "rule                                             \n"
      "{                                                \n"
      "  id \"NDNS RR Rule\"                            \n"
      "  for data                                       \n"
      "                                                 \n"
      "  filter                                         \n"
      "  {                                              \n"
      "    type name                                    \n"
      "    regex ^<>*<KEY|NDNS><>*$                     \n"
      "  }                                              \n"
      "  checker                                        \n"
      "  {                                              \n"
      "    type customized                              \n"
      "    sig-type rsa-sha256                          \n"
      "    key-locator                                  \n"
      "    {                                            \n"
      "      type name                                  \n"
      "      hyper-relation                             \n"
      "      {                                          \n"
      "        k-regex ^(<>*)<KEY>(<>*)<><ID-CERT>$     \n"
      "        k-expand \\\\1\\\\2                      \n"
      "        h-relation is-prefix-of                  \n"
      "        p-regex ^(<>*)[<KEY><NDNS>](<>*)<><>$    \n"
      "        p-expand \\\\1\\\\2                      \n"
      "      }                                          \n"
      "    }                                            \n"
      "                                                 \n"
      "  }                                              \n"
      "}                                                \n"
      "                                                 \n"
      "rule                                             \n"
      "{                                                \n"
      "  id \"App Data Rule\"                           \n"
      "  for data                                       \n"
      "                                                 \n"
      "  checker                                        \n"
      "  {                                              \n"
      "    type customized                              \n"
      "    sig-type rsa-sha256                          \n"
      "    key-locator                                  \n"
      "    {                                            \n"
      "      type name                                  \n"
      "      hyper-relation                             \n"
      "      {                                          \n"
      "        k-regex ^(<>*)<KEY>(<>*)<><ID-CERT>$     \n"
      "        k-expand \\\\1\\\\2                      \n"
      "        h-relation is-prefix-of                  \n"
      "        p-regex ^(<>*)$                          \n"
      "        p-expand \\\\1                           \n"
      "      }                                          \n"
      "    }                                            \n"
      "  }                                              \n"
      "}                                                \n"
      "                                                 \n"
      "trust-anchor                                     \n"
      "{                                                \n"
      "  ; type file                                    \n"
      "  ; file-name anchors/root.cert                  \n"
      "  type dir                                       \n"
      "  dir anchors                                    \n"
      "  refresh 1h                                     \n"
      "}                                                \n";
    std::ofstream os(m_validatorFile.c_str());
    os << str;
    os.close();
    NDNS_LOG_TRACE("FS: write validator configuration to " << m_validatorFile);
  }

  void
  saveLogConf()
  {
    std::string str =
      "log4j.rootLogger=TRACE, A1                                     \n"
      "log4j.appender.A1=org.apache.log4j.ConsoleAppender             \n"
      "log4j.appender.A1.layout=org.apache.log4j.PatternLayout        \n"
      "log4j.appender.A1.layout.ConversionPattern=%-5p %-15c - %m%n   \n";


    std::ofstream os("/usr/local/etc/ndns/log4cxx.properties");
    os << str;
    os.close();
    NDNS_LOG_TRACE("FS: write log4cxx configuration to " << m_validatorFile);
  }

  void
  addRr(Zone& zone, const Name& cert, const Name& rrLabel, const std::string& type, NdnsType ndnsType)
  {
    Rrset rrset(&zone);
    rrset.setLabel(rrLabel);
    name::Component rrType(type);
    rrset.setType(rrType);
    rrset.setTtl(zone.getTtl());

    Name name(zone.getName());
    name.append(label::NDNS_ITERATIVE_QUERY)
      .append(rrLabel)
      .append(rrType)
      .appendVersion();

    rrset.setVersion(name.get(-1));

    shared_ptr<Data> data = make_shared<Data>(name);
    Block block = nonNegativeIntegerBlock(::ndn::ndns::tlv::NdnsType, ndnsType);
    MetaInfo info;
    info.addAppMetaInfo(block);
    data->setMetaInfo(info);

    m_keyChain.sign(*data, cert);

    rrset.setData(data->wireEncode());

    m_dbMgr.insert(rrset);
    NDNS_LOG_TRACE("DB: zone " << zone << " add a "<< type << " RR with name="
                   << name << " rrLabel=" << rrLabel);
  }

  const Name
  createIdentity(const Name& id, const Name& parentCertName, Zone& parent, Zone& itself)
  {
    // parent's dsk and child's dsk are OK to sign RR
    if (itself != EMPTY_ZONE)
      this->addNsToDb(parent, itself, parentCertName);

    Name kskCertName = m_keyChain.createIdentity(id);
    Name kskName = m_keyChain.getDefaultKeyNameForIdentity(id);
    m_keyChain.deleteCertificate(kskCertName);
    auto kskCert = createCertificate(kskName, parentCertName, parent);

    Name dskName = m_keyChain.generateRsaKeyPair(id, false);
    m_keyChain.setDefaultKeyNameForIdentity(dskName);
    Name dskCert;

    if (itself != EMPTY_ZONE)
      dskCert = createCertificate(dskName, kskCert, itself);
    else
      dskCert = createCertificate(dskName, kskCert, parent);

    m_keyChain.setDefaultCertificateNameForKey(dskCert);

    return dskCert;
  }

  const Name
  createRoot(const Name& root)
  {
    m_rootCert = m_keyChain.createIdentity(root);
    NDNS_LOG_TRACE("FS: save root cert "<< m_rootCert << " to " << m_certDst);
    ndn::io::save(*(m_keyChain.getCertificate(m_rootCert)), m_certDst);

    Name dsk = m_keyChain.generateRsaKeyPair(root, false);
    auto cert = createCertificate(dsk, m_rootCert, m_rootZone);
    m_keyChain.setDefaultKeyNameForIdentity(dsk);
    m_keyChain.setDefaultCertificateNameForKey(cert);
    return cert;
  }


  const Name
  createCertificate(const Name& keyName, const Name& parentCertName, Zone& zone)
  {
    std::vector<CertificateSubjectDescription> desc;
    time::system_clock::TimePoint notBefore = time::system_clock::now();
    time::system_clock::TimePoint notAfter = notBefore + time::days(365);
    desc.push_back(CertificateSubjectDescription(oid::ATTRIBUTE_NAME,
                                                 "Signer: " + parentCertName.toUri()));
    shared_ptr<IdentityCertificate> cert =
      m_keyChain.prepareUnsignedIdentityCertificate(keyName, parentCertName,
                                                    notBefore, notAfter, desc, zone.getName());

    m_keyChain.sign(*cert, parentCertName);
    m_keyChain.addCertificateAsKeyDefault(*cert);
    NDNS_LOG_TRACE("KeyChain: add cert: " << cert->getName() << ". KeyLocator: "
                   << cert->getSignature().getKeyLocator().getName());

    this->addCertToDb(cert, zone);

    return cert->getName();
  }

  void
  addNsToDb(Zone& parent, Zone& child, const Name& certName, NdnsType ndnsType = NDNS_RESP)
  {
    Rrset rrset(&parent);
    Name label = child.getName().getSubName(parent.getName().size());
    rrset.setLabel(label);
    rrset.setType(label::NS_RR_TYPE);
    rrset.setTtl(parent.getTtl());

    Name name(parent.getName());
    name.append(label::NDNS_ITERATIVE_QUERY)
      .append(label)
      .append(label::NS_RR_TYPE)
      .appendVersion();

    rrset.setVersion(name.get(-1));

    shared_ptr<Data> data = make_shared<Data>(name);
    Block block = nonNegativeIntegerBlock(::ndn::ndns::tlv::NdnsType, ndnsType);
    MetaInfo info;
    info.addAppMetaInfo(block);
    data->setMetaInfo(info);

    m_keyChain.sign(*data, certName);

    rrset.setData(data->wireEncode());

    m_dbMgr.insert(rrset);
    NDNS_LOG_TRACE("DB: zone " << parent << " add a NS RR with name="
                   << name << " rrLabel=" << label);
  }

  void
  addCertToDb(shared_ptr<IdentityCertificate> cert, Zone& zone)
  {
    const Name& name = cert->getName();
    Rrset rrset(&zone);
    Name label = name.getPrefix(-2).getSubName(zone.getName().size() + 1);
    rrset.setLabel(label);
    rrset.setType(label::CERT_RR_TYPE);
    rrset.setVersion(cert->getName().get(-1));
    rrset.setTtl(zone.getTtl());
    rrset.setData(cert->wireEncode());

    m_dbMgr.insert(rrset);
    NDNS_LOG_TRACE("DB: zone " << zone << " add a ID-CERT RR with name=" << name << " rrLabel=" << label);
  }
public:
  Name m_root;
  Name m_ndn;
  Name m_edu;
  Name m_ucla;
  Name m_alice;
  Name m_bob;

  Zone m_rootZone;
  Zone m_ndnZone;
  Zone m_eduZone;
  Zone m_uclaZone;

  std::string m_certDst;

  Name m_rootCert;

  std::string m_configFile;

  KeyChain m_keyChain;

  std::string m_dbFile;
  std::string m_validatorFile;
  DbMgr m_dbMgr;

};
} // namespace ndns
} // namespace ndn

void
createDirIfNotExist(const std::string& dir)
{
  if (boost::filesystem::is_directory(dir))
    return;

  if(boost::filesystem::create_directories(dir)) {
    std::cerr << "create directory: " << dir << std::endl;
  }
  else {
    std::cerr << "CANNOT create dir" << dir << std::endl;
    exit(1);
  }
}

int
main(int argc, char* argv[])
{
  ndn::ndns::log::init();
  using std::string;
  using namespace ndn;
  using namespace ndn::ndns;

  Name root("/");
  std::string certFile = "/usr/local/etc/ndns/anchors/root-local.cert";
  std::string dbFile = "/usr/local/var/ndns/ndns.db";
  std::string configFile = "/usr/local/etc/ndns/ndns.conf";
  std::string validatorFile = "/usr/local/etc/ndns/validator.conf";

  try {
    namespace po = boost::program_options;
    po::variables_map vm;

    po::options_description generic("Generic Options");
    generic.add_options()("help,h", "print help message");

    po::options_description config("Configuration");
    config.add_options()
      // ("root,r", po::value<Name>(&root), "name of root")
      ("certFile,c", po::value<std::string>(&certFile), "the file to save root certificate")
      ("dbFile,d", po::value<std::string>(&dbFile), "database file")
      ;

    po::options_description hidden("Hidden Options");
    hidden.add_options()
      ;
    po::positional_options_description postion;

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
      std::cout << "Usage: ndns-demo [-r root] [-d rootCertDst]" << std::endl;
      std::cout << visible << std::endl;
      return 0;
    }
  }
  catch (const std::exception& ex) {
    std::cerr << "Parameter Error: " << ex.what() << std::endl;
    return 0;
  }
  catch (...) {
    std::cerr << "Parameter Unknown error" << std::endl;
    return 0;
  }

  std::cout << "Warning: This application will remove the existing identities: /, /ndn, "
            << "/ndn/edu, /ndn/edu/ucla, /ndn/edu/ucla/alice, /ndn/edu/ucla/bob"
            << " (if exist) and create new identities with these names"
            << std::endl;
  std::cout << "Warning: This application will clear all data in the specified database: " << dbFile
            << std::endl;
  std::cout << "Warning: This application will replace the root cert file with new content: "
            << certFile << std::endl;
  std::cout << "Warning: This application will replace the NdnsDaemon configuration file with new: "
            << configFile << std::endl;
  std::cout <<"Warning: This application may need sudo to run since the above resource "
            << "may be sensitive" << std::endl;
  std::cout << "Warnning: This applicaton will replace the Validator Configuration file with new: "
            << validatorFile << std::endl;

  // std::cout << std::endl << "Precondition: directory /usr/local/etc/ndns/anchors and "
  //  "/usr/local/var/ndns must be created " << "before this command" << std::endl;

  std::cout << "Do you want to continue? [Y|N]: ";

  char toDo = 'N';
  toDo = getchar();

  if (toDo != 'Y') {
    std::cout << "The application stops without doing anything" << std::endl;
    return 0;
  }


  createDirIfNotExist("/usr/local/etc/ndns/anchors");
  createDirIfNotExist("/usr/local/var/ndns");

  NdnsDemoData demo(root, certFile, configFile, dbFile, validatorFile);
  try {
    demo.run();
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl
              << "If you are writing/reading sensitive file, please try to run this command "
              << "with sudo" << std::endl;
  }
  return 0;
}
