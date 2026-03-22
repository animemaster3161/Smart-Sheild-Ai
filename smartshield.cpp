/*
 * ============================================================
 *  SmartShield AI Security — C++ Backend Server
 *  Port: 8080 | WinSock2 | Multi-threaded
 * ============================================================
 *
 *  YE FILE KYA KARTI HAI:
 *  Ye ek local HTTP server hai jo port 8080 pe sunti (listen karti) hai.
 *  Jab bhi Chrome Extension koi URL check karna chahti hai, wo is server
 *  ko request bhejti hai. Server URL analyze karke JSON response deta hai:
 *  { "status": "SAFE" / "BLOCKED" / "HTTP_WARNING", "score": X }
 * ============================================================
 */

// ── HEADERS ──────────────────────────────────────────────────
#include <iostream>    // cout ke liye (console print)
#include <string>      // string type ke liye
#include <map>         // key-value store (domain → stats)
#include <set>         // unique values ka collection (blacklist, whitelist)
#include <ctime>       // time() — rapid hit detection ke liye
#include <fstream>     // file read/write (blacklist.txt, logs.txt)
#include <sstream>     // string stream (JSON banana ke liye)
#include <algorithm>   // transform(), count() ke liye
#include <vector>      // ordered list (keywords, patterns)
#include <deque>       // double-ended queue — recent logs ke liye
#include <winsock2.h>  // Windows socket programming (network)
#include <windows.h>   // Windows API (threads, mutex)
#include <process.h>   // _beginthreadex — har client ke liye alag thread

#pragma comment(lib,"ws2_32.lib")  // WinSock library link karo

using namespace std;

// ============================================================
//  CONFIGURATION — ye numbers change karke behavior badal sakte ho
// ============================================================
const double THREAT_THRESHOLD  = 9.0;  // score iska se zyada ho to BLOCK karo
const int    TIME_WINDOW       = 8;    // itne seconds ke andar dobara aaye to "rapid" mana jayega
const int    RAPID_BLOCK_COUNT = 3;    // 3 baar rapid hit aaye to force block
const int    MAX_LOG_ENTRIES   = 200;  // memory mein kitne logs rakho
const string BLACKLIST_FILE    = "blacklist.txt";  // permanently blocked domains
const string LOG_FILE          = "logs.txt";       // sabki activity yahan likhi jaati hai

// ============================================================
//  WHITELIST — ye sites hamesha SAFE rahegi, score calculate nahi hoga
//  (Google, YouTube, Facebook etc. pe phishing check karna bakwaas hai)
// ============================================================
const set<string> WHITELIST = {
    "www.google.com","google.com","accounts.google.com",
    "mail.google.com","drive.google.com","gemini.google.com",
    "www.youtube.com","youtube.com",
    "www.facebook.com","facebook.com",
    "web.whatsapp.com","whatsapp.com",
    "www.instagram.com","instagram.com",
    "www.twitter.com","twitter.com","x.com",
    "www.linkedin.com","linkedin.com",
    "www.amazon.in","www.amazon.com","amazon.com","amazon.in",
    "www.flipkart.com","flipkart.com",
    "www.olx.in","olx.in",
    "github.com","www.github.com",
    "stackoverflow.com","www.stackoverflow.com",
    "claude.ai","www.claude.ai",
    "chat.openai.com","openai.com",
    "www.microsoft.com","microsoft.com",
    "login.microsoftonline.com",
    "outlook.live.com","outlook.office.com",
    "www.apple.com","apple.com","appleid.apple.com",
    "www.paypal.com","paypal.com",
    "www.netflix.com","netflix.com",
    "www.wikipedia.org","wikipedia.org",
    "iconscout.com","icons8.com",
    "www.search.ask.com"
};

// ============================================================
//  SUSPICIOUS TLDs — ye domain endings phishing mein bahut common hain
//  kyunki ye free ya bahut sasti milti hain, scammers inhe prefer karte hain
// ============================================================
const set<string> SUSPICIOUS_TLDS = {
    ".xyz",".tk",".ml",".ga",".cf",".gq",
    ".top",".work",".click",".link",".live",
    ".online",".site",".website",".tech",
    ".buzz",".icu",".monster",".rest",".fun",
    ".cam",".cfd",".cyou"
};

// ============================================================
//  BRAND KEYWORDS — bade brands ke naam
//  Agar koi domain mein ye naam hai lekin real domain nahi hai
//  (jaise "paypal-secure.xyz") to ye brand impersonation hai → +5 score
// ============================================================
const vector<string> BRAND_KEYWORDS = {
    "paypal","amazon","google","facebook","microsoft",
    "apple","netflix","instagram","whatsapp","twitter",
    "linkedin","youtube","gmail","outlook","onedrive",
    "icloud","dropbox","ebay","walmart","hdfc","icici",
    "sbi","paytm","phonepe","gpay","razorpay"
};

// ============================================================
//  PHISHING PATTERNS — ye strings real phishing URLs mein milti hain
//  Jaise: "secure-login-paypal.xyz" ya "account-verify-info.com"
// ============================================================
const vector<string> PHISHING_PATTERNS = {
    "login-verify","secure-login","account-verify",
    "bank-update","apple-id-","microsoft-verify",
    "free-gift","prize-claim","wallet-unlock","verify-now",
    "update-info","support-help","claim-reward",
    "-login.","-signin.","-secure.","-verify.",
    "confirm-","unlock-","restore-account",
    "security-alert","suspicious-activity","your-account"
};

// ============================================================
//  DATA STRUCTURES — domain ke baare mein info store karne ke liye
// ============================================================

// Ek domain ko kitni baar, kitni jaldi visit kiya gaya — track karne ke liye
struct SiteStats {
    int    hits      = 0;  // total kitni baar visit hua
    int    rapidHits = 0;  // kitne consecutive rapid hits (8 second ke andar)
    time_t lastSeen  = 0;  // last visit ka time (Unix timestamp)
};

// Log entry — ek URL check ka record
struct LogEntry {
    string timestamp;  // kab check hua
    string domain;     // kaunsa domain
    string status;     // SAFE / BLOCKED / WHITELISTED / HTTP_WARNING
    double score;      // kitna score mila
    string reason;     // kyun block/warn hua (e.g. "PHISHING_PATTERN, SUSPICIOUS_TLD")
};

// ============================================================
//  GLOBAL STATE — poore program mein share hota hai
//  (thread-safe rehne ke liye mtx_cs lock use hota hai)
// ============================================================
map<string, SiteStats> trafficData;   // domain → uski visit stats
set<string>            blacklist;     // blocked domains ka set
deque<LogEntry>        recentLogs;    // dashboard ke liye recent 200 logs
long long              totalChecked  = 0;  // total kitne URLs check hue
long long              totalBlocked  = 0;  // kitne block hue
long long              totalSafe     = 0;  // kitne safe the
long long              httpWarnings  = 0;  // kitne HTTP (no HTTPS) warnings
CRITICAL_SECTION       mtx_cs;        // mutex — ek time pe ek hi thread data touch kare

// ============================================================
//  PERSISTENCE — file se data load/save karna
// ============================================================

// Program start hote hi blacklist.txt padh lo
void loadBlacklist() {
    ifstream f(BLACKLIST_FILE);
    string line;
    while (getline(f, line))
        if (!line.empty()) blacklist.insert(line);
    cout << "[SmartShield] Loaded " << blacklist.size() << " blacklisted domains.\n";
}

// Naya domain block hua to blacklist.txt mein add karo (permanently)
void saveToBlacklist(const string& domain) {
    ofstream f(BLACKLIST_FILE, ios::app);  // ios::app = file ke end mein likho, overwrite mat karo
    f << domain << "\n";
}

// ============================================================
//  LOGGING
// ============================================================

// Current time ko readable string mein convert karo
string getTimestamp() {
    time_t now = time(0);
    char* dt = ctime(&now);   // ctime — "Mon Mar 20 14:32:10 2026\n" format
    string ts(dt);
    if (!ts.empty() && ts.back() == '\n') ts.pop_back();  // trailing newline hatao
    return ts;
}

// Ek entry logs.txt mein likho + memory mein bhi rakho (dashboard ke liye)
void addLog(const string& domain, const string& status, double score, const string& reason = "") {
    // File mein likho
    ofstream file(LOG_FILE, ios::app);
    string ts = getTimestamp();
    file << "[" << ts << "] " << domain
         << " | " << status << " | Score: " << score;
    if (!reason.empty()) file << " | " << reason;
    file << "\n";

    // Memory mein bhi rakho (dashboard /logs endpoint ke liye)
    LogEntry e;
    e.timestamp = ts;
    e.domain    = domain;
    e.status    = status;
    e.score     = score;
    e.reason    = reason;

    recentLogs.push_front(e);  // naya log sabse upar
    if ((int)recentLogs.size() > MAX_LOG_ENTRIES)
        recentLogs.pop_back();  // purana log nikalo agar limit se zyada ho
}

// ============================================================
//  URL UTILITIES — URL se domain nikalna
// ============================================================

// URL-encoded string decode karna (%20 → space, %3A → : etc.)
string urlDecode(const string& src) {
    string result;
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int val = 0;
            sscanf(src.substr(i + 1, 2).c_str(), "%x", &val);  // hex to int
            result += (char)val;
            i += 2;
        } else if (src[i] == '+') {
            result += ' ';  // + bhi space hota hai URL encoding mein
        } else {
            result += src[i];
        }
    }
    return result;
}

// URL se sirf domain nikalo
// "https://www.paypal-secure.xyz/login?id=123" → "www.paypal-secure.xyz"
string extractDomain(string url) {
    url = urlDecode(url);
    transform(url.begin(), url.end(), url.begin(), ::tolower);  // lowercase karo

    // "https://" ya "http://" hatao
    size_t proto = url.find("://");
    if (proto != string::npos) url = url.substr(proto + 3);

    // Path, query, fragment hatao (/ ? # ke baad sab hatao)
    for (char c : { '/', '?', '#' }) {
        size_t p = url.find(c);
        if (p != string::npos) url = url.substr(0, p);
    }

    // Port number hatao (":8080" etc.)
    size_t colon = url.find(":");
    if (colon != string::npos) url = url.substr(0, colon);

    // Trailing dot hatao agar ho
    if (!url.empty() && url.back() == '.') url.pop_back();

    return url;
}

// Domain ka TLD (last part) nikalo
// "paypal-secure.xyz" → ".xyz"
string getTLD(const string& domain) {
    size_t dot = domain.rfind(".");  // rfind = peeche se dhundho
    if (dot == string::npos) return "";
    return domain.substr(dot);
}

// Kya domain ek IP address hai? (e.g. 192.168.1.1)
// IP pe host karna suspicious hota hai — real websites domain use karti hain
bool isIPAddress(const string& domain) {
    int dots = 0;
    for (char c : domain) {
        if (c == '.') dots++;
        else if (!isdigit(c)) return false;  // koi bhi non-digit → IP nahi
    }
    return dots == 3;  // exactly 3 dots hone chahiye IPv4 mein
}

// Kya URL HTTP hai (HTTPS nahi)?
// HTTP mein data plain text mein jaata hai — koi encryption nahi
bool isHTTP(const string& rawUrl) {
    string lower = rawUrl;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return (lower.substr(0, 7) == "http://" &&
            lower.substr(0, 8) != "https://");
}

// ============================================================
//  HEURISTIC SCORING ENGINE — dil ki baat
//  Ye function URL ko dekhkar "kitna suspicious hai" ka number deta hai
//  Har suspicious cheez pe points add hote hain
//  Final score >= 9.0 → BLOCK
// ============================================================
pair<double, string> heuristicScore(const string& domain, const string& fullUrl) {
    double score = 0.0;
    vector<string> reasons;  // kyun points mile — ye UI mein dikhta hai

    // ── CHECK 1: IP address as host (+9.0) ──
    // Real websites IP pe nahi chalti (192.168.1.1/login.php = BAHUT suspicious)
    if (isIPAddress(domain)) {
        score += 9.0; reasons.push_back("IP_HOST");
    }

    // ── CHECK 2: Suspicious TLD (+4.0) ──
    // .xyz .tk .online jaise domains scammers ko free/sasti milti hain
    string tld = getTLD(domain);
    if (SUSPICIOUS_TLDS.count(tld)) {
        score += 4.0; reasons.push_back("SUSPICIOUS_TLD:" + tld);
    }

    // ── CHECK 3: Phishing pattern in domain name (+5.0) ──
    // Jaise "secure-login-paypal.xyz" mein "secure-login" pattern hai
    for (const auto& pat : PHISHING_PATTERNS) {
        if (domain.find(pat) != string::npos) {
            score += 5.0; reasons.push_back("PHISHING_PATTERN"); break;
        }
    }

    // ── CHECK 4: Brand impersonation (+5.0) ──
    // Agar domain mein "paypal" hai lekin ye "paypal.com" nahi hai
    // to ye PayPal ka fake page ho sakta hai
    for (const auto& brand : BRAND_KEYWORDS) {
        if (domain.find(brand) != string::npos) {
            // Legitimate domain check: paypal.com / www.paypal.com / paypal.in
            bool isReal = (domain == brand + ".com" ||
                           domain == "www." + brand + ".com" ||
                           domain == brand + ".in"  ||
                           domain == "www." + brand + ".in");
            if (!isReal) {
                score += 5.0; reasons.push_back("BRAND_IMPERSONATION:" + brand); break;
            }
        }
    }

    // ── CHECK 5: Long domain (+2.5) ──
    // Real websites ke domain chote hote hain
    // "secure-account-verify-login-paypal-support.xyz" = suspicious
    if ((int)domain.length() > 40) {
        score += 2.5; reasons.push_back("LONG_DOMAIN");
    }

    // ── CHECK 6: Bahut zyada hyphens (+1.5 per extra hyphen) ──
    // "paypal-secure-login-verify.com" mein 3 hyphens = suspicious
    int hyphens = (int)count(domain.begin(), domain.end(), '-');
    if (hyphens >= 3) {
        score += (hyphens - 2) * 1.5; reasons.push_back("HYPHENS:" + to_string(hyphens));
    }

    // ── CHECK 7: Deep subdomain (+2.0 per extra dot) ──
    // "login.verify.paypal.secure.xyz" = 4 dots = suspicious
    // Normal sites mein usually 1-2 dots hote hain (www.example.com)
    int dots = (int)count(domain.begin(), domain.end(), '.');
    if (dots >= 3) {
        score += (dots - 2) * 2.0; reasons.push_back("DEEP_SUBDOMAIN");
    }

    // ── CHECK 8: Numeric obfuscation (+2.0) ──
    // "paypall23secure456.com" — numbers daal ke real domain jaisa dikhana
    int digits = 0;
    for (char c : domain) if (isdigit(c)) digits++;
    if (digits >= 3) {
        score += 2.0; reasons.push_back("NUMERIC_OBFUSCATION");
    }

    // ── CHECK 9: Phishing pattern in URL PATH (+3.0) ──
    // Domain safe lag sakta hai lekin path suspicious ho
    // jaise "random-site.com/account-verify/paypal"
    string lurl = fullUrl;
    transform(lurl.begin(), lurl.end(), lurl.begin(), ::tolower);
    for (const auto& pat : PHISHING_PATTERNS) {
        if (lurl.find(pat) != string::npos) {
            score += 3.0; reasons.push_back("PATH_PATTERN"); break;
        }
    }

    // ── CHECK 10: HTTP (no TLS) (+4.0) ──
    // HTTPS nahi hai to data beech mein koi bhi padh sakta hai
    if (isHTTP(fullUrl)) {
        score += 4.0; reasons.push_back("HTTP_NO_TLS");
    }

    // Saare reasons ek string mein joddo (UI mein dikhane ke liye)
    string reasonStr;
    for (size_t i = 0; i < reasons.size(); i++) {
        if (i > 0) reasonStr += ", ";
        reasonStr += reasons[i];
    }
    return { score, reasonStr };
}

// ============================================================
//  JSON ESCAPE — special characters ko JSON safe banao
//  (double quotes, backslash etc. JSON todte hain)
// ============================================================
string jsonEscape(const string& s) {
    string out;
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else                out += c;
    }
    return out;
}

// ============================================================
//  MAIN CHECK FUNCTION — sabka baap
//  Extension yahan tak aati hai ek URL lekar
//  Return: JSON string {"status":"BLOCKED","score":14.0,"reason":"..."}
// ============================================================
string checkURL(const string& rawUrl) {
    string domain = extractDomain(rawUrl);

    // Chrome internal pages ko ignore karo (chrome://, file://, about:)
    if (domain.empty() ||
        rawUrl.substr(0, 9)  == "chrome://" ||
        rawUrl.substr(0, 19) == "chrome-extension://" ||
        rawUrl.substr(0, 7)  == "file://"  ||
        rawUrl.substr(0, 6)  == "about:")
    {
        return "{\"status\":\"SAFE\",\"domain\":\"\",\"score\":0}";
    }

    totalChecked++;

    // ── STEP 1: Whitelist check ──
    // Google, YouTube etc. — directly safe return karo
    // Lekin agar HTTP hai (jo unlikely hai) to warning do
    if (WHITELIST.count(domain)) {
        if (isHTTP(rawUrl)) {
            httpWarnings++;
            addLog(domain, "HTTP_WARNING", 4.0, "HTTP_NO_TLS (whitelisted domain)");
            return "{\"status\":\"HTTP_WARNING\",\"domain\":\"" + domain + "\",\"score\":4,\"reason\":\"HTTP_NO_TLS\"}";
        }
        totalSafe++;
        addLog(domain, "WHITELISTED", 0.0);
        return "{\"status\":\"SAFE\",\"domain\":\"" + domain + "\",\"score\":0}";
    }

    EnterCriticalSection(&mtx_cs);  // LOCK — ab sirf ye thread data touch karega

    // ── STEP 2: Blacklist check ──
    // Pehle se blocked domain hai? Seedha block karo, scoring ki zaroorat nahi
    if (blacklist.count(domain)) {
        totalBlocked++;
        LeaveCriticalSection(&mtx_cs);  // UNLOCK
        addLog(domain, "BLACKLISTED", 99.0);
        return "{\"status\":\"BLOCKED\",\"domain\":\"" + domain + "\",\"score\":99}";
    }

    // ── STEP 3: Heuristic scoring ──
    // URL ke features dekho aur score calculate karo
    pair<double,string> hresult = heuristicScore(domain, rawUrl);
    double hscore = hresult.first;
    string reason = hresult.second;

    // ── STEP 4: Frequency / Rapid-hit scoring ──
    // Ek domain ko baar baar jaldi jaldi access karna bhi suspicious ho sakta hai
    // (malware redirect loops ya automated phishing patterns)
    time_t now = time(0);
    SiteStats& stats = trafficData[domain];
    double gap = (stats.hits == 0) ? 9999.0 : difftime(now, stats.lastSeen);
    stats.hits++;
    stats.lastSeen = now;

    // Rapid hit streak track karo
    if (gap <= TIME_WINDOW) {
        stats.rapidHits++;       // TIME_WINDOW (8s) ke andar aaya = rapid
    } else {
        stats.rapidHits = 1;     // zyada gap = streak reset
    }

    // Base frequency score: baar baar visit karna thoda suspicious
    // NOTE: ye hits * 0.8 hai — 12 visits ke baad koi bhi site block ho sakti hai!
    // FIX: double fscore = min(stats.hits * 0.8, 4.0);  ← ye line use karo
    double fscore = stats.hits * 0.8;

    // Rapid hits ka extra score
    if (stats.rapidHits >= 2) {
        fscore += stats.rapidHits * 3.5;
        string tag = "RAPID_x" + to_string(stats.rapidHits);
        reason += reason.empty() ? tag : ", " + tag;
    }

    // 3 rapid hits = force block (redirect loop ka sign)
    if (stats.rapidHits >= RAPID_BLOCK_COUNT) {
        fscore += 15.0;  // threshold se bahut upar force kar do
        reason += ", FORCE_BLOCK_RAPID";
    }

    double total = hscore + fscore;  // final score = heuristic + frequency

    // ── STEP 5: HTTP warning ──
    // HTTP site hai lekin score threshold se neeche — warn karo, block nahi
    if (isHTTP(rawUrl) && total < THREAT_THRESHOLD) {
        httpWarnings++;
        addLog(domain, "HTTP_WARNING", total, reason);
        LeaveCriticalSection(&mtx_cs);
        ostringstream oss;
        oss << "{\"status\":\"HTTP_WARNING\",\"domain\":\"" << jsonEscape(domain)
            << "\",\"score\":" << total
            << ",\"reason\":\"" << jsonEscape(reason) << "\"}";
        return oss.str();
    }

    // ── STEP 6: Block decision ──
    // Score >= 9.0? BLOCK karo aur blacklist mein daal do (permanently)
    if (total >= THREAT_THRESHOLD) {
        blacklist.insert(domain);   // memory mein add
        saveToBlacklist(domain);    // file mein bhi save (server restart ke baad bhi block rahega)
        totalBlocked++;
        addLog(domain, "THREAT_DETECTED", total, reason);
        LeaveCriticalSection(&mtx_cs);

        ostringstream oss;
        oss << "{\"status\":\"BLOCKED\",\"domain\":\"" << jsonEscape(domain)
            << "\",\"score\":" << total
            << ",\"reason\":\"" << jsonEscape(reason) << "\"}";
        return oss.str();
    }

    // ── STEP 7: SAFE ──
    totalSafe++;
    addLog(domain, "SAFE_VISIT", total, reason.empty() ? "OK" : reason);
    LeaveCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "{\"status\":\"SAFE\",\"domain\":\"" << jsonEscape(domain)
        << "\",\"score\":" << total << "}";
    return oss.str();
}

// ============================================================
//  DASHBOARD API HANDLERS — /stats /logs /blacklist /unblock
//  Dashboard HTML in endpoints se data fetch karke UI mein dikhata hai
// ============================================================

// GET /stats → total checked, blocked, safe, warnings ka JSON
string handleStats() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "{"
        << "\"total\":"        << totalChecked  << ","
        << "\"safe\":"         << totalSafe     << ","
        << "\"blocked\":"      << totalBlocked  << ","
        << "\"http_warnings\":" << httpWarnings << ","
        << "\"blacklist_size\":" << blacklist.size()
        << "}";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /logs → recent 200 log entries ka JSON array
string handleLogs() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& e : recentLogs) {
        if (!first) oss << ",";
        first = false;
        oss << "{"
            << "\"ts\":\""     << jsonEscape(e.timestamp) << "\","
            << "\"domain\":\"" << jsonEscape(e.domain)    << "\","
            << "\"status\":\"" << jsonEscape(e.status)    << "\","
            << "\"score\":"    << e.score                 << ","
            << "\"reason\":\"" << jsonEscape(e.reason)    << "\""
            << "}";
    }
    oss << "]";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /blacklist → blocked domains ki list
string handleBlacklist() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& d : blacklist) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << jsonEscape(d) << "\"";
    }
    oss << "]";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /unblock?domain=xxx → user ne manually unblock kiya
// blocked.html pe "Continue Anyway" press karne pe yahan aata hai
string handleUnblock(const string& path) {
    string domain = "";
    size_t p = path.find("domain=");
    if (p != string::npos) {
        domain = path.substr(p + 7);
        size_t amp = domain.find("&"); if (amp != string::npos) domain = domain.substr(0, amp);
        // Basic URL decode
        string decoded;
        for (size_t i = 0; i < domain.size(); ++i) {
            if (domain[i] == '%' && i+2 < domain.size()) {
                int v = 0; sscanf(domain.substr(i+1,2).c_str(),"%x",&v);
                decoded += (char)v; i += 2;
            } else decoded += domain[i];
        }
        domain = decoded;
    }

    if (domain.empty()) return "{\"ok\":false,\"msg\":\"no domain\"}";

    EnterCriticalSection(&mtx_cs);
    blacklist.erase(domain);  // memory se hatao
    // blacklist.txt rewrite karo is domain ke bina
    ofstream f(BLACKLIST_FILE, ios::trunc);  // ios::trunc = puri file clear karo
    for (const auto& d : blacklist) f << d << "\n";
    LeaveCriticalSection(&mtx_cs);

    addLog(domain, "UNBLOCKED_BY_USER", 0.0, "Manual override");
    cout << "[SmartShield] User unblocked: " << domain << "\n";
    return "{\"ok\":true,\"domain\":\"" + jsonEscape(domain) + "\"}";
}

// HTTP response banana — status 200 + CORS headers + body
// CORS headers isliye chahiye kyunki browser extension alag origin se request bhejti hai
string buildResponse(const string& body, const string& contentType = "application/json") {
    ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Content-Type: " << contentType << "\r\n"
        << "Content-Length: " << body.length() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"           // kisi bhi origin ko allow karo
        << "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return oss.str();
}

// Browser pehle OPTIONS request bhejta hai (CORS preflight) — isko 200 se jawab do
string buildOptionsResponse() {
    return "HTTP/1.1 200 OK\r\n"
           "Access-Control-Allow-Origin: *\r\n"
           "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
           "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
           "Content-Length: 0\r\n"
           "Connection: close\r\n\r\n";
}

// ============================================================
//  PER-CLIENT THREAD — har incoming connection ke liye alag thread
//  Isse multiple tabs ek saath check ho sakti hain bina wait kiye
// ============================================================
struct ClientData { SOCKET socket; };

unsigned __stdcall handleClient(void* arg) {
    ClientData* cd = (ClientData*)arg;
    SOCKET client  = cd->socket;
    delete cd;  // heap memory free karo

    char buffer[8192] = {0};
    int bytes = recv(client, buffer, 8191, 0);  // client se data receive karo

    if (bytes > 0) {
        string request(buffer);

        // OPTIONS preflight — browser CORS check ke liye pehle ye bhejta hai
        if (request.substr(0, 7) == "OPTIONS") {
            string optResp = buildOptionsResponse();
            send(client, optResp.c_str(), (int)optResp.length(), 0);
            closesocket(client);
            return 0;
        }

        // Request line parse karo: "GET /path?query HTTP/1.1"
        string path = "/";
        size_t get_pos = request.find("GET ");
        if (get_pos != string::npos) {
            size_t start = get_pos + 4;
            size_t end   = request.find(" ", start);
            if (end != string::npos) path = request.substr(start, end - start);
        }

        string responseBody;

        // ── ROUTING — kaunsa endpoint call hua? ──
        if (path == "/stats" || path.substr(0, 6) == "/stats") {
            responseBody = buildResponse(handleStats());       // dashboard stats
        }
        else if (path == "/logs" || path.substr(0, 5) == "/logs") {
            responseBody = buildResponse(handleLogs());        // recent logs
        }
        else if (path == "/blacklist" || path.substr(0, 10) == "/blacklist") {
            responseBody = buildResponse(handleBlacklist());   // blocked domains
        }
        else if (path.substr(0, 8) == "/unblock") {
            responseBody = buildResponse(handleUnblock(path)); // manual unblock
        }
        else {
            // Main check: /?url=https://suspicious-site.xyz
            string url = "";
            size_t pos = request.find("url=");
            if (pos != string::npos) {
                url = request.substr(pos + 4);
                size_t sp  = url.find(" ");  if (sp  != string::npos) url = url.substr(0, sp);
                size_t amp = url.find("&");  if (amp != string::npos) url = url.substr(0, amp);
            }
            responseBody = buildResponse(checkURL(url));
        }

        send(client, responseBody.c_str(), (int)responseBody.length(), 0);  // response bhejo
    }

    closesocket(client);  // connection band karo
    return 0;
}

// ============================================================
//  MAIN — program ka entry point
//  Server start karo, connections sunna shuru karo
// ============================================================
int main() {
    InitializeCriticalSection(&mtx_cs);  // mutex initialize karo
    loadBlacklist();                      // blacklist.txt padhlo

    // WinSock initialize karo (Windows pe network use karne se pehle zaroorat hai)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "WinSock failed.\n"; return 1;
    }

    // Socket banao (AF_INET = IPv4, SOCK_STREAM = TCP)
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    // SO_REUSEADDR: server close hone ke baad port turant reuse ho sake
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // Server address configure karo
    sockaddr_in server{};
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;   // kisi bhi network interface se connection accept karo
    server.sin_port        = htons(8080);  // port 8080 (htons = host to network byte order)

    // Port se bind karo
    if (bind(server_fd, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        cout << "Bind failed. Port 8080 in use?\n"; return 1;
    }

    // Incoming connections sunna shuru karo
    listen(server_fd, SOMAXCONN);  // SOMAXCONN = OS ki maximum queue

    // Startup banner print karo
    cout << "\n";
    cout << "  ╔═══════════════════════════════════════════════════╗\n";
    cout << "  ║   SmartShield AI IPS Engine  v4.0                 ║\n";
    cout << "  ║   Port: 8080  |  Heuristic Engine: ACTIVE         ║\n";
    cout << "  ║   HTTP Detection: ON  |  Dashboard API: ON        ║\n";
    cout << "  ║                                                   ║\n";
    cout << "  ║   Endpoints:                                      ║\n";
    cout << "  ║     /?url=<URL>    → Check URL                    ║\n";
    cout << "  ║     /stats         → Live statistics              ║\n";
    cout << "  ║     /logs          → Recent log entries           ║\n";
    cout << "  ║     /blacklist     → Blocked domains list         ║\n";
    cout << "  ║                                                   ║\n";
    cout << "  ║   Dashboard: Open dashboard.html in browser       ║\n";
    cout << "  ╚═══════════════════════════════════════════════════╝\n\n";

    // ── MAIN LOOP — hamesha chalta rahe, connections accept karta rahe ──
    while (true) {
        // Naya connection aane ka wait karo (blocking call)
        SOCKET client = accept(server_fd, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        // Har client ke liye naya thread banao — ek client dusre ko block na kare
        ClientData* cd = new ClientData{client};
        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, handleClient, cd, 0, NULL);
        if (h) CloseHandle(h);  // thread handle close karo (thread khud chalti rahegi)
    }

    // Cleanup (practically yahan kabhi nahi pahunche kyunki loop infinite hai)
    DeleteCriticalSection(&mtx_cs);
    WSACleanup();
    return 0;
}
