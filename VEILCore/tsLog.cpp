//	Copyright (c) 2018, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

#include "stdafx.h"
#include <iostream>

static const char *levels[] = { "","Sens ", "Dev  ", "Trace", "Debug", "Info ", "Warn ", "Error", "Fatal" };
static const char *fulllevels[] = { "","Sensitive", "DevOnly", "Trace", "Debug", "Info", "Warn", "Error", "Fatal" };
#ifdef _DEBUG
static int gLog_minLevel = DEBUG_LEVEL_SENSITIVE;
#else
static int gLog_minLevel = DEBUG_LEVEL_TRACE;
#endif

PUSH_WARNINGS
IGNORE_WARNING(TS_DEPRECATED_WARNING)

static uint64_t highResClock()
{
#if defined(_MSC_VER)
    return __rdtsc();
#elif defined(__GNUC__) && (defined(__i386) || defined(__x86_64__))
    uint32_t hi, lo;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);
#elif defined(_MSC_VER)
    uint32_t hi, lo;

    __asm
    {
        rdtsc
        mov lo, eax
        mov hi, edx
    }
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);

#elif defined (_WIN32)
    union
    {
        LARGE_INTEGER liTime;
        struct tagHighLow {
            uint32_t low;
            uint32_t high;
        } lTime;
    } TimeValue;

    if (QueryPerformanceCounter(&TimeValue.liTime))
    {
        return *(uint64_t*)&TimeValue.liTime;
    }
    return 0;
#else
#endif
}


typedef tsLogOutput* tsLogOutputPtr;

typedef std::function<tsLogOutputPtr()> tsLogLamdaFn;

class tsLogOutputCreator
{
public:
    tsLogOutputCreator(const char *typeName, std::function<tsLogOutput *()> creator);
    ~tsLogOutputCreator();
    const char *getTypeName() const;
    tsLogOutput *CreateLogger() const;
protected:
    tscrypto::tsCryptoString _typeName;
    std::function<tsLogOutput *()> _creatorLambda;

private:
    tsLogOutputCreator(const tsLogOutputCreator& obj);
    tsLogOutputCreator &operator=(const tsLogOutputCreator &obj);
};


class tsLogMap
{
public:
    tsLogMap(const JSONObject& node);

    std::shared_ptr<tsLogOutput> Outputter() const { return _outputter; }
    void Outputter(std::shared_ptr<tsLogOutput>& setTo) { _outputter.reset(); _outputter = setTo; }
    const char *OutName() const { return _outName.c_str(); }
    bool Final() const { return _final; }
    bool UseThisOne(const char *outputName, int level) const;
protected:
    std::shared_ptr<tsLogOutput> _outputter;
    tscrypto::tsCryptoString _mapName;
    tscrypto::tsCryptoString _outName;
    int _level;
    int _minlevel;
    bool _final;
};

struct LogConfiguration
{
    tscrypto::AutoCriticalSection _lock;

    std::vector<std::shared_ptr<tsLogOutput> > _loggers;
    std::vector<std::shared_ptr<tsLogOutputCreator> > _loggerCreators;
    std::vector<std::shared_ptr<tsLogMap> > _maps;
    std::vector<std::shared_ptr<tsDebugConsumer> > m_unfilteredConsumerList;
    std::vector<std::shared_ptr<tsDebugConsumer> > m_consumerList;
    tscrypto::tsCryptoString _blacklist;
    std::shared_ptr<tsJsonPreferencesBase> _JsonPrefs;
};

static std::unique_ptr<LogConfiguration> tsLogConfig;

static void Configure()
{
    if (!tsLogConfig)
    {
        tsLogConfig.reset(new LogConfiguration());
#ifdef _DEBUG
        tsLog::DisallowLogs("CKM7,LOCKS,LOADER,INTERNAL,INFO1");
#else
        tsLog::DisallowLogs("CKM7,LOCKS,DEVONLY,INTERNAL,METADEBUG,METATRACE,LOADER,LOADERR,INFO1");
#endif
    }
}

#pragma region Helper classes not visible to users
class prefWatcher : public IPreferenceChangeNotify
{
public:
    virtual void OnPrefChange()
    {
        tsLog::Refresh();
    }
};

class tsLogToConsole : public tsLogOutput
{
public:
    virtual void WriteToOutput(const char *msg) override
    {
        std::cout << msg << std::endl;
    }
};
#ifdef _WIN32
class tsLogToOutputDebugString : public tsLogOutput
{
public:
    virtual void WriteToOutput(const char *msg) override
    {
        OutputDebugStringA(msg);
        OutputDebugStringA("\r\n");
    }
};
#else
class tsLogToOutputDebugString : public tsLogToConsole {};
#endif // _WIN32

#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(push)
#pragma warning(disable:4996)
#endif

class tsLogToFile : public tsLogOutput
{
public:
    tsLogToFile() :
        //_firstInit(true),
        _file(nullptr)
    {
    }
    ~tsLogToFile()
    {
        if (_file != nullptr)
            tsCloseFile(_file);
        _file = nullptr;
    }
    virtual void WriteToOutput(const char *msg) override
    {
        if (_file == nullptr)
            return;

        TSAUTOLOCKER locker(_lock);

        tscrypto::tsCryptoString tmp(msg);

        tmp += "\r\n";
        tsWriteFile(tmp.c_str(), 1, (uint32_t)tmp.size(), _file);
        //xp_FlushFile(_file);
    }
    virtual bool initialize(const JSONObject& node) override
    {
        if (!tsLogOutput::initialize(node))
            return false;

        tscrypto::tsCryptoString filename = node.AsString("filename");
        if (filename.size() == 0)
            return false;
        char path[MAX_PATH];

        tsGetSpecialFolder(tsSft_LogFolder, path, sizeof(path));
        if (tsStrLen(path) > 0 && path[tsStrLen(path) - 1] != XP_PATH_SEP_CHAR && path[tsStrLen(path) - 1] != ':')
            tsStrCat(path, sizeof(path), XP_PATH_SEP_STR);
        tsStrCat(path, sizeof(path), filename.c_str());
        tsStrCat(path, sizeof(path), ".log");
        _filename = path;
        if (node.AsBool("deleteFile", false))
        {
            tsDeleteFile(_filename.c_str());
        }
        if (tsFOpen(&_file, path, "ab+", tsShare_DenyNO) != 0)
            return false;
        return true;
    }
private:
    tscrypto::tsCryptoString _filename;
    //bool _firstInit;
    TSFILE _file;
    tscrypto::AutoCriticalSection _lock;
};
class tsLogToConsumer : public tsLogOutput
{
public:
    void WriteToLog(const tscrypto::tsCryptoString& loggerName, int level, tscrypto::tsCryptoString& msg) override
    {
        tscrypto::tsCryptoString tmp(getFormatString());
        tscrypto::tsCryptoString thread;
        tscrypto::tsCryptoString time;
        tscrypto::tsCryptoString timestamp;
        TSTHREAD_ID threadId;

        threadId = tsGetCurrentThreadId();
        thread.Format("t%08x", (uint32_t)(intptr_t)threadId);
        time.Format("%16llx", highResClock());
        timestamp = tscrypto::tsCryptoDate::Now().ToLocal().ToString();

        tmp.Replace("{$time}", time.c_str()).Replace("{$timestamp}", timestamp.c_str()).Replace("{$msg}", msg).Replace("{$thread}", thread.c_str()).Replace("{$logger}", tscrypto::tsCryptoString(loggerName).TruncOrPadRight(10, ' ').c_str()).Replace("{$level}", levels[level]);
        while (tmp.size() > 0)
        {
            tsLog::WriteToConsumers(loggerName, level, tmp.substring(0, 2048));
            tmp.DeleteAt(0, 2048);
        }
    }
};
#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(pop)
#endif

class tsLogToNull : public tsLogOutput
{
public:
    void WriteToLog(const tscrypto::tsCryptoString& loggerName, int level, tscrypto::tsCryptoString& msg) override
    {
        UNREFERENCED_PARAMETER(loggerName);
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(msg);
    }
};

#pragma endregion

#pragma region tsLog components
tsLogOutput::tsLogOutput()
{
    _formatter = "{$msg}";
}

tsLogOutput::tsLogOutput(const tsLogOutput &obj)
{
    UNREFERENCED_PARAMETER(obj);
}

tsLogOutput::~tsLogOutput()
{
}

tsLogOutput &tsLogOutput::operator=(const tsLogOutput &obj)
{
    UNREFERENCED_PARAMETER(obj);
    return *this;
}

void tsLogOutput::setFormatString(const char *formatter)
{
    _formatter = formatter;
}

void tsLogOutput::WriteToLog(const tscrypto::tsCryptoString& loggerName, int level, tscrypto::tsCryptoString& msg)
{
    tscrypto::tsCryptoString tmp(_formatter);
    tscrypto::tsCryptoString thread;
    tscrypto::tsCryptoString time;
    tscrypto::tsCryptoString timestamp;
    TSTHREAD_ID threadId;

    threadId = tsGetCurrentThreadId();

    Configure();
    thread.Format("t%08x", (uint32_t)(intptr_t)threadId);

    tscrypto::tsCryptoString tmpMsg;
    tmpMsg << IndentData() << msg;
    time.Format("%16llx", highResClock());
    timestamp = tscrypto::tsCryptoDate::Now().ToLocal().ToString();

    tmp
        .Replace("{$time}", time.c_str())
        .Replace("{$timestamp}", timestamp.c_str())
        .Replace("{$msg}", tmpMsg.c_str())
        .Replace("{$thread}", thread.c_str())
        .Replace("{$logger}", tscrypto::tsCryptoString(loggerName).TruncOrPadRight(10, ' ').c_str())
        .Replace("{$level}", levels[level]);
    WriteToOutput(tmp.c_str());
}

tscrypto::tsCryptoString tsLogOutput::getName() const
{
    return _name;
}

bool tsLogOutput::initialize(const JSONObject& node)
{
    _name = node.AsString("id");
    if (_name.size() == 0)
        return false;
    _formatter = node.AsString("formatter");
    if (_formatter.size() == 0)
        _formatter = "{$msg}";
    return true;
}

void tsLogOutput::indent()
{
    _indent += "  ";
}

void tsLogOutput::outdent()
{
    if (_indent.size() > 0)
        _indent.resize(_indent.size() - 2);
}

tscrypto::tsCryptoString &tsLogOutput::IndentData()
{
    return _indent;
}

tsLogOutputCreator::tsLogOutputCreator(const char *typeName, std::function<tsLogOutput *()> creator) :
    _typeName(typeName),
    _creatorLambda(creator)
{
}

tsLogOutputCreator::~tsLogOutputCreator()
{
}

const char *tsLogOutputCreator::getTypeName() const
{
    return _typeName.c_str();
}

tsLogOutput *tsLogOutputCreator::CreateLogger() const
{
    return _creatorLambda();
}

tsLogOutputCreator::tsLogOutputCreator(const tsLogOutputCreator& obj)
{
    UNREFERENCED_PARAMETER(obj);
}

tsLogOutputCreator &tsLogOutputCreator::operator=(const tsLogOutputCreator &obj)
{
    UNREFERENCED_PARAMETER(obj);
    return *this;
}




static int FindLevel(const char *str)
{
    if (str == nullptr || str[0] == 0)
        return -1;

    for (int i = 1; i < sizeof(fulllevels) / sizeof(fulllevels[0]); i++)
    {
        if (tsStriCmp(fulllevels[i], str) == 0)
            return i;
    }
    return -1;
}

static int FindLevel(tscrypto::tsCryptoString str)
{
    return FindLevel(str.c_str());
}

tsLogMap::tsLogMap(const JSONObject& node)
{
    _mapName = node.AsString("id");
    _outName = node.AsString("outputTo");
    _level = FindLevel(node.AsString("level"));
    _minlevel = FindLevel(node.AsString("minlevel"));
    _final = node.AsBool("final", false);
}

bool tsLogMap::UseThisOne(const char *outputName, int level) const
{
    if (tsStriCmp(_mapName.c_str(), outputName) != 0 && _mapName != "*")
        return false;

    if (level < gLog_minLevel)
        level = gLog_minLevel;
    if (level > DEBUG_LEVEL_FATAL_ERROR)
        level = DEBUG_LEVEL_FATAL_ERROR;

    if (_level != -1 && _level != level)
        return false;
    if (_minlevel != -1 && _minlevel > level)
        return false;
    return true;
}

#pragma endregion


#if (_MSC_VER >= 1700)
void tsLog::RegisterLoggerCreator(const char *typeName, std::function<tsLogOutput *()> creator)
{
    ::Configure();
    UnregisterLoggerCreator(typeName);

    TSAUTOLOCKER locker(tsLogConfig->_lock);
    tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator(typeName, creator)));
}
#endif

void tsLog::RegisterLoggerCreator(const char *typeName, tsLogOutput *(*creator)())
{
    ::Configure();
    UnregisterLoggerCreator(typeName);

    TSAUTOLOCKER locker(tsLogConfig->_lock);
    tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator(typeName, creator)));
}

void tsLog::UnregisterLoggerCreator(const char *typeName)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    auto it = std::find_if(tsLogConfig->_loggerCreators.begin(), tsLogConfig->_loggerCreators.end(), [typeName](std::shared_ptr<tsLogOutputCreator> &creator) { return (tsStriCmp(creator->getTypeName(), typeName) == 0); });
    if (it != tsLogConfig->_loggerCreators.end())
        tsLogConfig->_loggerCreators.erase(it);
}

void tsLog::UnregisterAllLoggerCreators()
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    tsLogConfig->_loggerCreators.clear();
}

void tsLog::WriteToLog(const char *_loggerName, int level, const char *_msg)
{
    tsCryptoString loggerName(_loggerName), msg(_msg);

    if (!WillLog(_loggerName, level))
        return;
    ::Configure();
    WriteToUnfilteredConsumers(loggerName, level, msg);
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    if (tsLogConfig->_loggers.size() == 0)
    {
        return;
    }
    std::find_if(tsLogConfig->_maps.begin(), tsLogConfig->_maps.end(), [&](std::shared_ptr<tsLogMap> &map) ->bool {
        std::shared_ptr<tsLogOutput> outputter;

        if (!map->UseThisOne(_loggerName, level))
            return false;

        if (map->OutName() != nullptr && map->OutName()[0] != 0)
        {
            if (map->Outputter() == nullptr)
            {
                std::vector<std::shared_ptr<tsLogOutput> >::iterator logIter = std::find_if(tsLogConfig->_loggers.begin(), tsLogConfig->_loggers.end(), [&](std::shared_ptr<tsLogOutput> &logger)->bool {
                    if (tsStriCmp(logger->getName().c_str(), map->OutName()) == 0)
                    {
                        outputter = logger;
                        return true;
                    }
                    return false;
                });
                if (logIter == tsLogConfig->_loggers.end())
                    return map->Final();
                map->Outputter(outputter);
            }
            else
            {
                outputter = map->Outputter();
                //                outputter = map.Outputter();
            }

            if (!!outputter)
            {
                outputter->WriteToLog(loggerName, level, msg);
                return map->Final();
            }
        }
        else
        {
            return map->Final();
        }
        return map->Final();
    });
}

void tsLog::CreateDefaultLoggerCreators()
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    if (tsLogConfig->_loggerCreators.size() == 0)
    {
        tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator("DebugString",
            []()->tsLogOutputPtr
        {
            return new tsLogToOutputDebugString();
        }
        )));
        tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator("Console", []()->tsLogOutput * {return new tsLogToConsole; })));
        tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator("File", []()->tsLogOutput * {return new tsLogToFile; })));
        tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator("Consumer", []()->tsLogOutput * {return new tsLogToConsumer; })));
        tsLogConfig->_loggerCreators.push_back(std::shared_ptr<tsLogOutputCreator>(new tsLogOutputCreator("Null", []()->tsLogOutput * {return new tsLogToNull; })));
    }
}

void tsLog::SetApplicationJsonPreferences(std::shared_ptr<tsJsonPreferencesBase> prefs)
{
    ::Configure();
    tsLogConfig->_JsonPrefs.reset();
    if (prefs != nullptr)
    {
        tsLogConfig->_JsonPrefs = std::dynamic_pointer_cast<tsJsonPreferencesBase>(prefs);
        prefs->loadValues();

        CreateDefaultLoggerCreators();
        Refresh();
    }
}
std::shared_ptr<tsJsonPreferencesBase> tsLog::GetApplicationJsonPreferences() { ::Configure(); return tsLogConfig->_JsonPrefs; }

void tsLog::ConfigureJson(const tscrypto::tsCryptoStringBase &json)
{
    JSONObject node;

    if (node.FromJSON(json.c_str()))
    {
        JSONElement* element = node.findSingleItem("$.Outputs", false);
        if (dynamic_cast<JSONField*>(element) != nullptr)
        {
            ConfigureOutputs(*((JSONField*)element));
        }
        element = node.findSingleItem("$.Map", false);
        if (dynamic_cast<JSONField*>(element) != nullptr)
        {
            ConfigureMaps(*((JSONField*)element));
        }
        element = node.findSingleItem("$.Whitelist", false);
        if (dynamic_cast<JSONField*>(element) != nullptr)
        {
            ConfigureWhitelist(*((JSONField*)element));
        }
        element = node.findSingleItem("$.Blacklist", false);
        if (dynamic_cast<JSONField*>(element) != nullptr)
        {
            ConfigureBlacklist(*((JSONField*)element));
        }
        //element = node.findSingleItem("$.ReleaseOverride", false);
        //if (dynamic_cast<JSONField*>(element) != nullptr)
        //{
        //	gLog_minLevel = DEBUG_LEVEL_DEV_ONLY;
        //}
    }
}

void tsLog::ConfigureJsonMaps(const tscrypto::tsCryptoStringBase &mapJson)
{
    ::Configure();
    if (mapJson.size() > 0)
    {
        JSONObject mapsNode;

        if (mapsNode.FromJSON(mapJson.c_str()))
        {
            ConfigureMaps(mapsNode.field("Map"));
        }
    }
}

void tsLog::ConfigureMaps(const JSONField& mapsNode)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    tscrypto::tsCryptoString Results;

    if (mapsNode.Type() != JSONField::jsonArray)
        return;

    tsLogConfig->_maps.clear();

    mapsNode.for_each([](const JSONField& fld) {
        if (fld.Type() == JSONField::jsonObject)
        {
            tsLogConfig->_maps.push_back(std::shared_ptr<tsLogMap>(new tsLogMap(fld.AsObject())));
        }
    });
}

void tsLog::ConfigureJsonOutputs(const tscrypto::tsCryptoStringBase &outputsJson)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    if (outputsJson.size() > 0)
    {
        JSONObject outputsNode;

        if (outputsNode.FromJSON(outputsJson.c_str()))
        {
            ConfigureOutputs(outputsNode.field("Outputs"));
        }
    }
}

void tsLog::ConfigureOutputs(const JSONField& outputsNode)
{
    CreateDefaultLoggerCreators();

    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    tscrypto::tsCryptoString Results;

    tsLogConfig->_loggers.clear();
    tsLogConfig->_maps.clear();

    outputsNode.for_each([](const JSONField& fld) {
        if (fld.Type() == JSONField::jsonObject)
        {
            const JSONObject& o = fld.AsObject();

            tscrypto::tsCryptoString type = o.AsString("type");
            std::vector<std::shared_ptr<tsLogOutputCreator> >::iterator iter = std::find_if(tsLogConfig->_loggerCreators.begin(), tsLogConfig->_loggerCreators.end(), [&type](std::shared_ptr<tsLogOutputCreator> &creator) ->bool {
                if (tsStriCmp(creator->getTypeName(), type.c_str()) == 0)
                    return true;
                return false;
            });
            if (iter != tsLogConfig->_loggerCreators.end())
            {
                std::shared_ptr<tsLogOutput> outputter = std::shared_ptr<tsLogOutput>((*iter)->CreateLogger());
                if (outputter != nullptr)
                {
                    if (outputter->initialize(o))
                    {
                        tsLogConfig->_loggers.push_back(outputter);
                    }
                }
            }
        }
    });

    std::shared_ptr<tsLogOutput> outputter = std::shared_ptr<tsLogOutput>(new tsLogToNull);
    if (!!outputter)
    {
        JSONObject o;

        o
            .add("id", "Null")
            .add("type", "Null");

        outputter->initialize(o);
        tsLogConfig->_loggers.push_back(outputter);
    }
}

void tsLog::ConfigureJsonBlacklist(const tscrypto::tsCryptoStringBase &listJson)
{
    if (listJson.size() > 0)
    {
        JSONObject listNode;

        if (listNode.FromJSON(listJson.c_str()))
        {
            ConfigureBlacklist(listNode.field("Blacklist"));
        }
    }
}

void tsLog::ConfigureBlacklist(const JSONField& listNode)
{
    DisallowLogs(listNode.AsString().c_str());
}

void tsLog::ConfigureJsonWhitelist(const tscrypto::tsCryptoStringBase &listJson)
{
    if (listJson.size() > 0)
    {
        JSONObject listNode;

        if (listNode.FromJSON(listJson.c_str()))
        {
            ConfigureWhitelist(listNode.field("Whitelist"));
        }
    }
}

void tsLog::ConfigureWhitelist(const JSONField& listNode)
{
    AllowLogs(listNode.AsString().c_str());
}

#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(push)
#pragma warning(disable:4996)
#endif

void tsLog::Refresh()
{
    ::Configure();

    if (!!tsLogConfig->_JsonPrefs)
    {
        JsonPreferenceItem item = tsLogConfig->_JsonPrefs->findPreferenceItem(tsLogConfig->_JsonPrefs->GetDebugSettingsName());
        if (item.Location != jc_NotFound)
        {
            ConfigureJson(item.Value);
        }
    }
    else
    {
        return;
    }
}
#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(pop)
#endif

void tsLog::AddMasterConsumer(std::shared_ptr<tsDebugConsumer> consumer)
{
    ::Configure();
    if (!!consumer)
    {
        if (consumer->WantsUnfiltered())
            tsLogConfig->m_unfilteredConsumerList.push_back(consumer);
        else
            tsLogConfig->m_consumerList.push_back(consumer);
    }
}

//static int findConsumer(tsDebugConsumer *data, tsDebugConsumer *matcher)
//{
//    if (data == matcher)
//        return 1;
//    return 0;
//}

void tsLog::RemoveMasterConsumer(std::shared_ptr<tsDebugConsumer> consumer)
{
    ::Configure();
    if (consumer != NULL)
    {
        tsLogConfig->m_unfilteredConsumerList.erase(std::remove_if(tsLogConfig->m_unfilteredConsumerList.begin(), tsLogConfig->m_unfilteredConsumerList.end(), [consumer](std::shared_ptr<tsDebugConsumer>& obj)->bool { return obj == consumer; }), tsLogConfig->m_unfilteredConsumerList.end());
        tsLogConfig->m_consumerList.erase(std::remove_if(tsLogConfig->m_consumerList.begin(), tsLogConfig->m_consumerList.end(), [consumer](std::shared_ptr<tsDebugConsumer>& obj)->bool { return obj == consumer; }), tsLogConfig->m_consumerList.end());
    }
}

void tsLog::ClearMasterConsumers()
{
    ::Configure();
    tsLogConfig->m_consumerList.clear();
    tsLogConfig->m_unfilteredConsumerList.clear();
}

void tsLog::WriteToConsumers(const tscrypto::tsCryptoStringBase &category, int priority, const tscrypto::tsCryptoStringBase &message)
{
    ::Configure();
    for (size_t i = 0; i < tsLogConfig->m_consumerList.size(); i++)
    {
        std::shared_ptr<tsDebugConsumer> consumer = tsLogConfig->m_consumerList[i];

        if (!!consumer)
        {
            consumer->WriteLine(category, priority, message);
        }
    }
}

void tsLog::WriteToUnfilteredConsumers(const tscrypto::tsCryptoStringBase &category, int priority, const tscrypto::tsCryptoStringBase &message)
{
    ::Configure();
    for (size_t i = 0; i < tsLogConfig->m_unfilteredConsumerList.size(); i++)
    {
        std::shared_ptr<tsDebugConsumer> consumer = tsLogConfig->m_unfilteredConsumerList[i];

        if (!!consumer)
        {
            consumer->WriteLine(category, priority, message);
        }
    }
}

void tsLog::AddJsonMap(const tscrypto::tsCryptoStringBase &Json)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    JSONObject o;

    if (o.FromJSON(Json.c_str()))
    {
        tsLogConfig->_maps.push_back(std::shared_ptr<tsLogMap>(new tsLogMap(o)));
    }
}

void tsLog::ClearMaps()
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    tsLogConfig->_maps.clear();
}

void tsLog::AllowLogs(const char *logList)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    tscrypto::tsCryptoString tmp(logList);
    tmp.Trim();
    tscrypto::tsCryptoStringList splits = tmp.split(",");
    for (tscrypto::tsCryptoString& log : *splits)
    {
        log.Trim().ToUpper().prepend("[").append("]");
        tsLogConfig->_blacklist.Replace(log.c_str(), "");
    }
}

void tsLog::DisallowLogs(const char *logList)
{
    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);

    tscrypto::tsCryptoString tmp(logList);
    tmp.Trim();
    tscrypto::tsCryptoStringList splits = tmp.split(",");
    for (tscrypto::tsCryptoString &log : *splits)
    {
        log.Trim().ToUpper().prepend("[").append("]");
        tsLogConfig->_blacklist.Replace(log.c_str(), "");
        tsLogConfig->_blacklist.append(log.c_str());
    }
}

bool tsLog::WillLog(const char *loggerName, int level)
{
    if (loggerName == nullptr || *loggerName == 0)
        return false;
    if (level < gLog_minLevel)
        return false;
    if (level > DEBUG_LEVEL_FATAL_ERROR)
        return false;

    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    if (tsLogConfig->_loggers.size() == 0 && tsLogConfig->m_consumerList.empty() && tsLogConfig->m_unfilteredConsumerList.empty())
    {
        return false;
    }
    if (tsLogConfig->_maps.size() == 0 && tsLogConfig->m_consumerList.empty() && tsLogConfig->m_unfilteredConsumerList.empty())
    {
        return false;
    }
    char buff[50];
    tsStrCpy(buff, sizeof(buff), "[");
    tsStrCat(buff, sizeof(buff), loggerName);
    tsStrCat(buff, sizeof(buff), "]");
    tsStrUpr(buff, sizeof(buff));

    if (strstr(tsLogConfig->_blacklist.c_str(), buff) != nullptr)
        return false;
    return true;
}

void tsLog::indent(const char *loggerName, int level)
{
    if (!WillLog(loggerName, level))
        return;

    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    if (tsLogConfig->_loggers.size() == 0)
    {
        return;
    }
    std::find_if(tsLogConfig->_maps.begin(), tsLogConfig->_maps.end(), [&](std::shared_ptr<tsLogMap> &map) ->bool {
        std::shared_ptr<tsLogOutput> outputter;

        if (!map->UseThisOne(loggerName, level))
            return false;

        if (map->OutName() != nullptr && map->OutName()[0] != 0)
        {
            if (map->Outputter() == nullptr)
            {
                std::vector<std::shared_ptr<tsLogOutput> >::iterator logIter = std::find_if(tsLogConfig->_loggers.begin(), tsLogConfig->_loggers.end(), [&](std::shared_ptr<tsLogOutput> &logger)->bool {
                    if (tsStriCmp(logger->getName().c_str(), map->OutName()) == 0)
                    {
                        outputter = logger;
                        return true;
                    }
                    return false;
                });
                if (logIter == tsLogConfig->_loggers.end())
                    return map->Final();
                map->Outputter(outputter);
            }
            else
                outputter = map->Outputter();
            if (!!outputter)
            {
                outputter->indent();
                return map->Final();
            }
        }
        else
        {
            return map->Final();
        }
        return map->Final();
    });
}

void tsLog::outdent(const char *loggerName, int level)
{
    if (!WillLog(loggerName, level))
        return;

    ::Configure();
    TSAUTOLOCKER locker(tsLogConfig->_lock);
    if (tsLogConfig->_loggers.size() == 0)
    {
        return;
    }
    std::find_if(tsLogConfig->_maps.begin(), tsLogConfig->_maps.end(), [&](std::shared_ptr<tsLogMap> &map) ->bool {
        std::shared_ptr<tsLogOutput> outputter;

        if (!map->UseThisOne(loggerName, level))
            return false;

        if (map->OutName() != nullptr && map->OutName()[0] != 0)
        {
            if (map->Outputter() == nullptr)
            {
                std::vector<std::shared_ptr<tsLogOutput> >::iterator logIter = std::find_if(tsLogConfig->_loggers.begin(), tsLogConfig->_loggers.end(), [&](std::shared_ptr<tsLogOutput> &logger)->bool {
                    if (tsStriCmp(logger->getName().c_str(), map->OutName()) == 0)
                    {
                        outputter = logger;
                        return true;
                    }
                    return false;
                });
                if (logIter == tsLogConfig->_loggers.end())
                    return map->Final();
                map->Outputter(outputter);
            }
            else
                outputter = map->Outputter();
            if (!!outputter)
            {
                outputter->outdent();
                return map->Final();
            }
        }
        else
        {
            return map->Final();
        }
        return map->Final();
    });
}

POP_WARNINGS
