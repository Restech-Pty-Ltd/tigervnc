/* This object handles the processing of the Whitelist JSON file and determines if the incomming connection should be allowed */

#ifndef __RFB_JSONWhiteList_H__
#define __RFB_JSONWhiteList_H__

#include <string.h>
#include <sys/types.h>
#include <nlohmann/json.hpp>
#include <iostream>

namespace rfb {

  class JSONWhiteList {
  public:
    JSONWhiteList(const char* fname);
    ~JSONWhiteList();

    // isWhitelisted() determines if the client with the given IP address is allowed to connect
    bool isWhitelisted(std::string name);

  protected:
    bool reloadEntries();
    
  protected:
    char* fileName;
    time_t lastModTime; // last modification time of the file, this allows us to reload the file if it has changed
    nlohmann::json data; // contains the JSON data from the file
  };

}
#endif
