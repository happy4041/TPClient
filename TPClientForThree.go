package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	Trace    *log.Logger
	Info     *log.Logger
	Warning  *log.Logger
	Error    *log.Logger
	clientip string
	nasip    string
	mac      string
	secret   = "Eshore!@#"
	jar, _   = cookiejar.New(nil)
	client   = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

var (
	username  string
	password  string
	dpassword string
)

const (
	CTJSON       = "application/json"
	CTURL        = "application/x-www-form-urlencoded"
	WEBPORTAL    = "http://enet.10000.gd.cn:10001"
)

type Json struct {
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	Clientip      string `json:"clientip"`
	Nasip         string `json:"nasip"`
	Mac           string `json:"mac"`
	Iswifi        string `json:"iswifi,omitempty"`
	Timestamp     string `json:"timestamp"`
	Authenticator string `json:"authenticator"`
}

func main() {
	flag.Parse()
	if username == "" || password == "" {
		usage()
	}

	if !isDeviceLogin() {
		deviceLogin()
		waitForReconnect()
	}
	if !isLogin() {
		login()
	}
}

func init() {
	Trace = log.New(ioutil.Discard, "TRACE: ", log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	flag.StringVar(&username, "u", "", "set `username`.")
	flag.StringVar(&password, "p", "", "set network portal `password`.")
	flag.StringVar(&dpassword, "d", "123456", "set device portal `password`, this is optional.")
	flag.StringVar(&mac, "m", "", "set mac `address`, this is optional. If you connet by your router, this must be the mac address of your router.")
	flag.Usage = usage
}

func usage() {
	fmt.Print(`                    ___         ___                                     ___           ___
                   /\  \       /\__\                                   /\__\         /\  \                  
      ___         /::\  \     /:/  /                      ___         /:/ _/_        \:\  \         ___     
     /\__\       /:/\:\__\   /:/  /                      /\__\       /:/ /\__\        \:\  \       /\__\    
    /:/  /      /:/ /:/  /  /:/  /  ___   ___     ___   /:/__/      /:/ /:/ _/_   _____\:\  \     /:/  /    
   /:/__/      /:/_/:/  /  /:/__/  /\__\ /\  \   /\__\ /::\  \     /:/_/:/ /\__\ /::::::::\__\   /:/__/     
  /::\  \      \:\/:/  /   \:\  \ /:/  / \:\  \ /:/  / \/\:\  \__  \:\/:/ /:/  / \:\~~\~~\/__/  /::\  \     
 /:/\:\  \      \::/__/     \:\  /:/  /   \:\  /:/  /   ~~\:\/\__\  \::/_/:/  /   \:\  \       /:/\:\  \    
 \/__\:\  \      \:\  \      \:\/:/  /     \:\/:/  /       \::/  /   \:\/:/  /     \:\  \      \/__\:\  \   
      \:\__\      \:\__\      \::/  /       \::/  /        /:/  /     \::/  /       \:\__\          \:\__\  
       \/__/       \/__/       \/__/         \/__/         \/__/       \/__/         \/__/           \/__/  
TPClient version: TPClinet/1.0.3
Usage: TPClient -u <username> -p <password> [-d password] [-m address]

Options:
`)
	flag.PrintDefaults()
	os.Exit(0)
}

func checkNetworkStatus() bool {
	conn, err := net.DialTimeout("tcp", "114.114.114.114:53", 5*time.Second)
	for err == nil {
		conn.Close()
		time.Sleep(10 * time.Second)
		conn, err = net.DialTimeout("tcp", "114.114.114.114:53", 5*time.Second)
	}
	return true
}

func isDeviceLogin() bool {
	conn, err := net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	if err == nil {
		conn.Close()
		Info.Println("Device is logged in.")
		return true
	}
	Info.Println("Device ready to log in.")
	return false
}

func deviceLogin() {
	req, err := http.NewRequest("POST", "http://172.17.18.3:8080/portal/pws?t=li&ifEmailAuth=false",strings.NewReader("userName="+url.QueryEscape(username)+"&userPwd="+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(dpassword)))+"&userDynamicPwd=&userDynamicPwdd=&serviceType=&userurl=&userip=&basip=&language=Chinese&usermac=null&wlannasid=&wlanssid=&entrance=null&loginVerifyCode=&userDynamicPwddd=&customPageId=100&pwdMode=0&portalProxyIP=172.17.18.3&portalProxyPort=50200&dcPwdNeedEncrypt=1&assignIpType=0&appRootUrl=http%3A%2F%2F172.17.18.3%3A8080%2Fportal%2F&manualUrl=&manualUrlEncryptKey="))
	if err != nil {
        // handle error
    }
	req.Header.Set("Accept", "text/plain, */*; q=0.01")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Length", "408")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "hello1="+url.QueryEscape(username)+"; hello2=false")
	req.Header.Set("DNT", "1")
	req.Header.Set("Host", "172.17.18.3:8080")
	req.Header.Set("Origin", "http://172.17.18.3:8080")
	req.Header.Set("Referer", "http://172.17.18.3:8080/portal/templatePage/20200426133232935/login_custom.jsp")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	Info.Println("Device login successful. RR")
}

func waitForReconnect() {
	conn, err := net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	for err != nil {
		conn, err = net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	}
	conn.Close()
}

func isLogin() bool {
	resp, _ := client.Get("http://www.qq.com/")
	location, _ := resp.Location()
	if strings.Contains(location.String(), "www.qq.com") {
		Info.Println("Already logged into the campus network")
		return true
	}
	Info.Println("Ready to log into the campus network.")
	return false
}

func login() {
	resp, _ := client.Get("http://www.qq.com")
	location, _ := resp.Location()
	resp, _ = client.Get(location.String())
	jar.SetCookies(location, resp.Cookies())
	r, _ := regexp.Compile("wlanuserip=(.*?)&wlanacip=(.*)")
	ip := r.FindStringSubmatch(location.String())
	clientip = ip[1]
	nasip = ip[2]

	getMacAddr(clientip)
	code := getVerifyCode()
	doLogin(code)
}

func getMacAddr(wwwIp string) string {
	if mac != "" {
		mac = strings.ReplaceAll(mac, ":", "-")
		Info.Println("MAC address:" + mac + ".")
		return mac
	}

	ifs, _ := net.Interfaces()
	for _, ifInfo := range ifs {
		ips, _ := ifInfo.Addrs()
		for _, ip := range ips {
			if strings.Contains(ip.String(), wwwIp) {
				mac = strings.ReplaceAll(ifInfo.HardwareAddr.String(), ":", "-")
				Info.Println("MAC address:" + mac + ".")
				return mac
			}
		}
	}
	return ""
}

func paramInit() *Json {
	jsonObject := &Json{}
	jsonObject.Username = username
	jsonObject.Clientip = clientip
	jsonObject.Nasip = nasip
	jsonObject.Mac = mac
	return jsonObject
}

func getVerifyCode() string {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+secret)))
	jsonObject := paramInit()
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/challenge", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	r, _ := regexp.Compile("\"challenge\":\"(.*?)\"")
	code := r.FindStringSubmatch(string(body))
	Info.Println("Verify Code:" + code[1] + ".")
	return code[1]
}

func doLogin(code string) {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+code+secret)))
	jsonObject := paramInit()
	jsonObject.Password = password
	jsonObject.Iswifi = "4060"
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/login", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	r, _ := regexp.Compile("\"rescode\":\"(.*?)\"")
	result := r.FindStringSubmatch(string(body))
	if !strings.Contains(result[1], "0") {
		r, _ = regexp.Compile("\"resinfo\":\"(.*?)\"")
		msg := r.FindStringSubmatch(string(body))
		Error.Println("Login Error." + msg[1])
		os.Exit(1)
	}
	Info.Println("Login successful.")
}

func doLogout() {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+secret)))
	jsonObject := paramInit()
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/logout", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	Info.Println("Logout successful.")
}

func keepAlive() {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+secret)))
	param := fmt.Sprintf("username=%s&clientip=%s&nasip=%s&mac=%s&timestamp=%s&authenticator=%s", username, clientip, nasip, mac, timestamp, authenticator)
	resp, _ := client.Post(WEBPORTAL+"/hbservice/client/active", CTURL, strings.NewReader(param))

	body, _ := ioutil.ReadAll(resp.Body)
	Info.Println(string(body))
}
