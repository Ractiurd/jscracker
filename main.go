package main

import (
	"Net/http"
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/mgutz/ansi"
)

func main() {
	logo()

	var url string
	flag.StringVar(&url, "u", "", "js link to find secrets")

	var file string
	flag.StringVar(&file, "f", "", "File path of the urls")

	flag.Parse()

	//Read from the file path
	if url == "" && file != "" {
		read, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer read.Close()
		scanner := bufio.NewScanner(read)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			link := scanner.Text()
			okay(link)

		}
	}

	//Read from the stdin
	if url == "" && file == "" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			link := scanner.Text()
			okay(link)

		}

	}
	//Read from url value
	if url != "" && file == "" {
		link := url
		okay(link)

	}

}

func okay(link string) {
	//making the get request
	lg1 := ansi.Color(link, "red")
	fmt.Printf("******%v*******\n\n", lg1)
	defer fmt.Printf("\n\n\n")

	resp, err := http.Get(link)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	//getting the response body

	body, errs := io.ReadAll(resp.Body)

	if err != nil {
		panic(errs)
	}

	body_string := string(body)

	//google api key

	google_api := regexp.MustCompile("AIza[0-9A-Za-z\\-_]{35}")
	match1 := google_api.FindAllString(body_string, -1)

	for _, matchvar := range match1 {
		if matchvar != "" {
			fmt.Printf("google api key >> %v \n", matchvar)
		}

	}

	//auth basic
	auth_basic := regexp.MustCompile("basic [a-zA-Z0-9_\\-:\\.=]+")
	match2 := auth_basic.FindAllString(body_string, -1)

	for _, matchvar := range match2 {
		if matchvar != "" {
			fmt.Printf("Auth Basic >> %v \n", matchvar)
		}

	}

	//auth bearer
	auth_bearer := regexp.MustCompile("bearer [a-zA-Z0-9_\\-\\.=]+")
	match3 := auth_bearer.FindAllString(body_string, -1)

	for _, matchvar := range match3 {
		if matchvar != "" {
			fmt.Printf("Auth Bearer >> %v \n", matchvar)
		}

	}

	//auth http
	auth_http := regexp.MustCompile(`(https?://)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+`)
	match4 := auth_http.FindAllString(body_string, -1)

	for _, matchvar := range match4 {
		if matchvar != "" {
			fmt.Printf("Auth Http >>%v  >> %v\n", matchvar, link)
		}

	}

	//aws client id
	aws_client := regexp.MustCompile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
	match5 := aws_client.FindAllString(body_string, -1)

	for _, matchvar := range match5 {
		if matchvar != "" {
			fmt.Printf("Aws Client >> %v \n", matchvar)
		}

	}

	//aws keys
	aws_keys := regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}")
	match6 := aws_keys.FindAllString(body_string, -1)

	for _, matchvar := range match6 {
		if matchvar != "" {
			fmt.Printf("Aws Keys >> %v \n", matchvar)
		}

	}

	//aws mvs key
	aws_mvs_keys := regexp.MustCompile("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
	match7 := aws_mvs_keys.FindAllString(body_string, -1)

	for _, matchvar := range match7 {
		if matchvar != "" {
			fmt.Printf("Aws mvs Keys >> %v \n", matchvar)
		}

	}

	//aws secret key
	aws_secret_keys := regexp.MustCompile("(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]")
	match8 := aws_secret_keys.FindAllString(body_string, -1)

	for _, matchvar := range match8 {
		if matchvar != "" {
			fmt.Printf("Aws Secret Keys >> %v \n", matchvar)
		}

	}

	//cloudinary-basic-auth
	cloudinary_basic_auth := regexp.MustCompile("cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
	match10 := cloudinary_basic_auth.FindAllString(body_string, -1)

	for _, matchvar := range match10 {
		if matchvar != "" {
			fmt.Printf("cloudinary-basic-auth >> %v \n", matchvar)
		}

	}

	//facebook access token
	facebook_acess_token := regexp.MustCompile("EAACEdEose0cBA[0-9A-Za-z]+")
	match11 := facebook_acess_token.FindAllString(body_string, -1)

	for _, matchvar := range match11 {
		if matchvar != "" {
			fmt.Printf("Facebook Acess Token >> %v \n", matchvar)
		}

	}

	//facebook client id
	facebook_client_id := regexp.MustCompile("(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}")
	match12 := facebook_client_id.FindAllString(body_string, -1)

	for _, matchvar := range match12 {
		if matchvar != "" {
			fmt.Printf("Facebook Client Id >> %v \n", matchvar)
		}

	}

	//facebook secret key
	facebook_secret_key := regexp.MustCompile("(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}")
	match14 := facebook_secret_key.FindAllString(body_string, -1)

	for _, matchvar := range match14 {
		if matchvar != "" {
			fmt.Printf("Facebook Secret Key >> %v \n", matchvar)
		}

	}

	//google cloud key
	google_cloud_key := regexp.MustCompile("(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}")
	match15 := google_cloud_key.FindAllString(body_string, -1)

	for _, matchvar := range match15 {
		if matchvar != "" {
			fmt.Printf("google cloud key >> %v \n", matchvar)
		}

	}

	//google oauth token
	google_0auth_token := regexp.MustCompile("ya29.[0-9A-Za-z\\-_]+")
	match16 := google_0auth_token.FindAllString(body_string, -1)

	for _, matchvar := range match16 {
		if matchvar != "" {
			fmt.Printf("google oauth token >> %v \n", matchvar)
		}

	}

	//heroku api key
	heroku_api_key := regexp.MustCompile("[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
	match17 := heroku_api_key.FindAllString(body_string, -1)

	for _, matchvar := range match17 {
		if matchvar != "" {
			fmt.Printf("heroku api key >> %v \n", matchvar)
		}

	}

	//ipv4
	ipv4 := regexp.MustCompile("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
	match18 := ipv4.FindAllString(body_string, -1)

	for _, matchvar := range match18 {
		if matchvar != "" {
			fmt.Printf("Ipv4 >> %v \n", matchvar)
		}

	}

	//json sec
	json := regexp.MustCompile("(\\\\?\"|&quot;|%22)[a-z0-9_-]*(api[_-]?key|S3|aws_|secret|PASSWD|PASS|Secret|Auth|passw|auth)[a-z0-9_-]*(\\\\?\"|&quot;|%22): ?(\\\\?\"|&quot;|%22)[^\"&]+(\\\\?\"|&quot;|%22)")
	match19 := json.FindAllString(body_string, -1)

	for _, matchvar := range match19 {
		if matchvar != "" {
			fmt.Printf("Json Sec >> %v \n", matchvar)
		}

	}

	//linkedin
	linkedin := regexp.MustCompile("(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]")
	match20 := linkedin.FindAllString(body_string, -1)

	for _, matchvar := range match20 {
		if matchvar != "" {
			fmt.Printf("Linkedin >> %v \n", matchvar)
		}

	}

	//linkedin secret
	linkedin_secret := regexp.MustCompile("(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]")
	match21 := linkedin_secret.FindAllString(body_string, -1)

	for _, matchvar := range match21 {
		if matchvar != "" {
			fmt.Printf("Linkedin Secret >> %v \n", matchvar)
		}

	}

	//mailchamp
	mailchamp := regexp.MustCompile("[0-9a-f]{32}-us[0-9]{1,2}")
	match22 := mailchamp.FindAllString(body_string, -1)

	for _, matchvar := range match22 {
		if matchvar != "" {
			fmt.Printf("Mailchamp >> %v \n", matchvar)
		}

	}

	//mailgun api key
	mailgun := regexp.MustCompile("key-[0-9a-zA-Z]{32}")
	match23 := mailgun.FindAllString(body_string, -1)

	for _, matchvar := range match23 {
		if matchvar != "" {
			fmt.Printf("Mailgun >> %v \n", matchvar)
		}

	}

	//md5
	md5 := regexp.MustCompile("[a-f0-9]{32}")
	match24 := md5.FindAllString(body_string, -1)

	for _, matchvar := range match24 {
		if matchvar != "" {
			fmt.Printf("MD5 >> %v \n", matchvar)
		}

	}

	//picatic api
	picatic := regexp.MustCompile("sk_live_[0-9a-z]{32}")
	match25 := picatic.FindAllString(body_string, -1)

	for _, matchvar := range match25 {
		if matchvar != "" {
			fmt.Printf("Picatic Api >> %v \n", matchvar)
		}

	}

	//s3 buckets
	s3 := regexp.MustCompile("[a-z0-9.-]+\\.s3\\.amazonaws\\.com")
	match26 := s3.FindAllString(body_string, -1)

	for _, matchvar := range match26 {
		if matchvar != "" {
			fmt.Printf("S3 Buckets >> %v \n", matchvar)
		}

	}

	s31 := regexp.MustCompile("[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com")
	match27 := s31.FindAllString(body_string, -1)

	for _, matchvar := range match27 {
		if matchvar != "" {
			fmt.Printf("S3 Buckets >> %v \n", matchvar)
		}

	}
	s32 := regexp.MustCompile("[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)")
	match28 := s32.FindAllString(body_string, -1)

	for _, matchvar := range match28 {
		if matchvar != "" {
			fmt.Printf("S3 Buckets >> %v \n", matchvar)
		}

	}

	s33 := regexp.MustCompile("//s3\\.amazonaws\\.com/[a-z0-9._-]+")
	match29 := s33.FindAllString(body_string, -1)

	for _, matchvar := range match29 {
		if matchvar != "" {
			fmt.Printf("S3 Buckets >> %v \n", matchvar)
		}

	}

	s34 := regexp.MustCompile("//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+")
	match30 := s34.FindAllString(body_string, -1)

	for _, matchvar := range match30 {
		if matchvar != "" {
			fmt.Printf("S3 Buckets >> %v \n", matchvar)
		}

	}

	//slack token
	slack1 := regexp.MustCompile("xox[baprs]-([0-9a-zA-Z]{10,48})?")
	match31 := slack1.FindAllString(body_string, -1)

	for _, matchvar := range match31 {
		if matchvar != "" {
			fmt.Printf("Slack Token >> %v \n", matchvar)
		}

	}

	//slack webhook
	slack2 := regexp.MustCompile("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}")
	match32 := slack2.FindAllString(body_string, -1)

	for _, matchvar := range match32 {
		if matchvar != "" {
			fmt.Printf("Slack webhook >> %v \n", matchvar)
		}

	}

	//square secret
	square := regexp.MustCompile("sq0csp-[ 0-9A-Za-z\\-_]{43}")
	match33 := square.FindAllString(body_string, -1)

	for _, matchvar := range match33 {
		if matchvar != "" {
			fmt.Printf("square secret >> %v \n", matchvar)
		}

	}

	//square token
	square1 := regexp.MustCompile("sqOatp-[0-9A-Za-z\\-_]{22}")
	match34 := square1.FindAllString(body_string, -1)

	for _, matchvar := range match34 {
		if matchvar != "" {
			fmt.Printf("square token >> %v \n", matchvar)
		}

	}

	//stripe key
	stripe := regexp.MustCompile("(?:r|s)k_live_[0-9a-zA-Z]{24}")
	match35 := stripe.FindAllString(body_string, -1)

	for _, matchvar := range match35 {
		if matchvar != "" {
			fmt.Printf("stripe key >> %v \n", matchvar)
		}

	}

	//twilio keys
	twilio := regexp.MustCompile("SK[0-9a-fA-F]{32}")
	match36 := twilio.FindAllString(body_string, -1)

	for _, matchvar := range match36 {
		if matchvar != "" {
			fmt.Printf("Twilio key >> %v \n", matchvar)
		}

	}

	//twitter key
	twitter := regexp.MustCompile("(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}")
	match37 := twitter.FindAllString(body_string, -1)

	for _, matchvar := range match37 {
		if matchvar != "" {
			fmt.Printf("twitter key >> %v \n", matchvar)
		}

	}

	//twitter oauth
	twitter1 := regexp.MustCompile("[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]")
	match38 := twitter1.FindAllString(body_string, -1)

	for _, matchvar := range match38 {
		if matchvar != "" {
			fmt.Printf("twitter auth >> %v \n", matchvar)
		}

	}

	//twitter secret
	twitter2 := regexp.MustCompile("(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}")
	match39 := twitter2.FindAllString(body_string, -1)

	for _, matchvar := range match39 {
		if matchvar != "" {
			fmt.Printf("twitter secret >> %v \n", matchvar)
		}

	}

	//end of the if func
}

// logo
func logo() {
	lg1 := ansi.Color("****         ****", "green")
	lg2 := ansi.Color("*****       *****", "green")
	lg3 := ansi.Color("*******    ******", "green")
	lg4 := ansi.Color("*** **** **** ***", "green")
	lg5 := ansi.Color("***  *******  ***", "green")
	lg6 := ansi.Color("***           ***", "green")
	lg7 := ansi.Color("***           ***", "green")
	lg8 := ansi.Color("***           *** >> Created by Ractiurd [Mahedi]", "green")
	lg9 := ansi.Color("\nJS Secret Finder \n\n", "green")

	fmt.Println(lg1)
	fmt.Println(lg2)
	fmt.Println(lg3)
	fmt.Println(lg4)
	fmt.Println(lg5)
	fmt.Println(lg6)
	fmt.Println(lg7)
	fmt.Println(lg8)
	fmt.Println(lg9)

}
