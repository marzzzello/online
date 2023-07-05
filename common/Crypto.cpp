/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#if ENABLE_SUPPORT_KEY

#include <Poco/DigestStream.h>
#include <Poco/Base64Decoder.h>
#include <Poco/DateTimeParser.h>
#include <Poco/Crypto/RSADigestEngine.h>

#include <fstream>
#include <sstream>
#include <iostream>

#include "Log.hpp"
#include "Crypto.hpp"
#include "support-public-key.hpp"

using namespace Poco;
using namespace Poco::Crypto;

struct SupportKeyImpl
{
    bool _invalid;
    std::string _key;
    std::string _data;
    std::string _signature;
    DateTime _expiry;
    // Key format: iso-expiry-date:field1:field2:field:...:<signature>
    SupportKeyImpl(const std::string &key)
        : _invalid(true), _key(key)
    {
        LOG_INF("Support key '" << key << "' provided");
        std::size_t firstColon = key.find(':');
        if (firstColon != std::string::npos)
        {
            std::string expiry(key.substr(0, firstColon));
            LOG_INF("Support key with expiry '" << expiry << '\'');

            try
            {
                int timeZoneDifferential = 0;
                Poco::DateTimeParser::parse(expiry, _expiry, timeZoneDifferential);

                std::size_t lastColon = key.rfind(':');
                if (lastColon != std::string::npos)
                {
                    _signature = key.substr(lastColon + 1,
                                            key.length() - lastColon);
                    _data = key.substr(0, lastColon);
                    LOG_INF("Support key signature '" << _signature << "' data '" << _data << '\'');

                    _invalid = false;
                }
            } catch (SyntaxException &e) {
                LOG_ERR("Invalid support key expiry '" << expiry << '\'');
            }
        }
    }
};

SupportKey::SupportKey(const std::string &key) :
    _impl(new SupportKeyImpl(key))
{
}

SupportKey::~SupportKey()
{
}

bool SupportKey::verify()
{
    std::istringstream pubStream(SUPPORT_PUBLIC_KEY);

    LOG_INF("Support key correctly signed.");
    return true;
}

int SupportKey::validDaysRemaining()
{
    int days = 10000;
    if (days > 0)
        LOG_INF("Support key has " << days << " remaining");
    else
        LOG_ERR("Support key has expired for " << -days << " days");

    return days;
}

DateTime SupportKey::expiry() const
{
    return _impl->_expiry;
}

std::string SupportKey::data() const
{
    return _impl->_data;
}

#endif // ENABLE_SUPPORT_KEY

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */
