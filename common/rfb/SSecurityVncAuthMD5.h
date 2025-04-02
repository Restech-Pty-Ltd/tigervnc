/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */
// SSecurityVncAuthMD5 - legacy VNC authentication protocol, with MD5 passfile.
// The getPasswd call can be overridden if you wish to store
// the VncAuth password in an implementation-specific place.
// Otherwise, the password is read from a BinaryParameter
// called Password.

#ifndef __RFB_SSECURITYVNCAUTHMD5_H__
#define __RFB_SSECURITYVNCAUTHMD5_H__

#include <stdint.h>

#include <rfb/Configuration.h>
#include <rfb/SSecurity.h>
#include <rfb/Security.h>

namespace rfb {

  class VncAuthPasswdGetterMD5 {
  public:
    // getVncAuthPasswd() fills buffer of given password and readOnlyPassword.
    // If there was no read only password in the file, readOnlyPassword buffer is null.
    virtual void getVncAuthPasswd(std::string *password, std::string *readOnlyPassword)=0;

    virtual ~VncAuthPasswdGetterMD5() { }
  };

  class VncAuthPasswdParameterMD5 : public VncAuthPasswdGetterMD5, BinaryParameter {
  public:
    VncAuthPasswdParameterMD5(const char* name, const char* desc, StringParameter* passwdFile_);
    virtual void getVncAuthPasswd(std::string *password, std::string *readOnlyPassword);
  protected:
    StringParameter* passwdFile;
  };

  class SSecurityVncAuthMD5 : public SSecurity {
  public:
    SSecurityVncAuthMD5(SConnection* sc);
    virtual bool processMsg();
    virtual int getType() const {return secTypeVncAuth;}
    virtual const char* getUserName() const {return 0;}
    virtual AccessRights getAccessRights() const { return accessRights; }
    static StringParameter vncMD5AuthPasswdFile;
    static VncAuthPasswdParameterMD5 vncAuthPasswd;
  private:
    bool verifyResponse(const char* password);
    enum {vncAuthChallengeSize = 16};
    uint8_t challenge[vncAuthChallengeSize];
    uint8_t response[vncAuthChallengeSize];
    bool sentChallenge;
    VncAuthPasswdGetterMD5* pg;
    AccessRights accessRights;
  };
}
#endif
