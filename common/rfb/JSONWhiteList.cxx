
/* This object handles the processing of the Whitelist JSON file and determines if the incomming connection should be allowed */
#include <rfb/JSONWhiteList.h>
#include <rfb/LogWriter.h>
#include <sys/stat.h>

/* We use this library to provide better network segment functions */
#include <boost/asio/ip/network_v4.hpp>

#include <fstream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace rfb;

static LogWriter vlog("JSONWhiteList");

JSONWhiteList::JSONWhiteList(const char* fname) : fileName(NULL), lastModTime(0)
{
  if (fname != NULL)
  {
    fileName = strdup((char*)fname);
    reloadEntries();
  }
    
}

JSONWhiteList::~JSONWhiteList()
{
}

bool JSONWhiteList::isWhitelisted(std::string client_ip)
{
  
  if (fileName == NULL)
    return false;

  if (!reloadEntries()) {
    vlog.error("Could not read IP filtering rules: rejecting all clients");
    return false;
  }

  if (!data.contains("whitelisted")) {
    vlog.error("No 'whitelisted' key in the JSON file: rejecting all clients");
    return false;
  }

  /* If the Jason file exits, but the whitelist list is empty, (or has a blank entry) accept all incoming connections. */
  if ((data["whitelisted"].empty()) || (data["whitelisted"].size() == 1 && data["whitelisted"][0]["ip"].get<std::string>().empty()))
  {
    vlog.debug("Empty 'whitelisted' array in the JSON file: accepting all clients");
    return true;
  }

  // iterate the array
  for (const auto& entry : data["whitelisted"]) {
    std::string ip = entry["ip"];
    std::string mask = entry["mask"];

    if (!mask.empty()) {
      // IP/mask format (CIDR notation)
      // we use the boost library to check if the client IP is in the range of the IP/mask. 
      // This test is done using network segments and checking if the client IP is a subnet of the IP/mask.
      try {
        boost::asio::ip::network_v4 network = boost::asio::ip::make_network_v4(ip + '/' + mask);

        // create target address
        boost::asio::ip::network_v4 addr = boost::asio::ip::make_network_v4(client_ip + "/32");

        if (addr.is_subnet_of(network)) {
          return true;
        }

      }
      catch (std::exception& e) {
        // Ignore invalid IP/mask entries
      }
    }
    else {
      // Single IP address
      if (ip == client_ip) {
        return true;
      }
    }
  }
  return false;
  
}

bool JSONWhiteList::reloadEntries()
{
  if (fileName == NULL)
    return true;

  struct stat st;
  if (stat(fileName, &st) != 0)
    return false;

  if (st.st_mtime != lastModTime) {
    // Actually reload only if the file was modified
    FILE* fp = fopen(fileName, "r");
    if (fp == NULL)
      return false;

    // Parse the file contents as JSON
    data = json::parse(fp);

    

    fclose(fp);
    lastModTime = st.st_mtime;
  }
  return true;
}

