package sanitizer

import "testing"

var (
	lowerLetters          = "abcdefghijklmnopqrstuwxyz"
	upperLetters          = "ABCDEFGHIJKLMNOPQRSTUWXYZ"
	numbers               = "1234567890"
	characters            = "!\"#$%&'()*+,-./:;>=<?@[\\]^_{|}~`"
	htmlOpeningCharacters = "<html><body><h1>"
	xmlOpeningCharacters  = "<html><body><h1>"
	htmlClosingCharacters = "</h1></body></html>"
	xmlClosingCharacters  = "</h1></body></html>"
	scriptOpening         = "<script>"
	embedOpening          = "<embed>"
	objectOpening         = "<object>"
	scriptClosing         = "</script>"
	embedClosing          = "</embed>"
	objectClosing         = "</object>"
	scriptDocument        = "document.body.style.backgroundColor = \"lightblue\";"
	uriTestUrl            = "https://example.com/test-page?param1=value1&param2=value2"
	uriTestEmail          = "mailto:test@example.com?subject=Hello%20World"
	uriTestTelephone      = "tel:555-1234"
	uriTestGeo            = "geo:37.7749,-122.4194?q=Golden%20Gate%20Bridge"
	uriTestFtp            = "ftp://ftp.examples.com/myfile.txt"
	uriTestNews           = "news:comp.infosystems.www.authoring.html"
	uriTestData           = "data:text/plain;charset=utf-8,Hello%2C%20world!"
	uriTestFile           = "file:///C:/Users/JohnDoe/Documents/myfile.txt"
	uriTestBitcoin        = "bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
	uriTest1              = "josh:jimenez"

	URLTest = "https://www.example.com/index.html?query=example#section1"

	XSSTest = "<script>alert(\"Hello, world!\");</script>"
)

func TestAlpha(t *testing.T) {
	type args struct {
		input  string
		spaces bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test only lowerLetters",
			args: args{
				input:  lowerLetters,
				spaces: true,
			},
			want: lowerLetters,
		},
		{
			name: "Test lowerLetters and upperLetters",
			args: args{
				input:  lowerLetters + upperLetters,
				spaces: true,
			},
			want: lowerLetters + upperLetters,
		},
		{
			name: "Test lowerLetters and numbers",
			args: args{
				input:  lowerLetters + numbers,
				spaces: true,
			},
			want: lowerLetters,
		},
		{
			name: "Test lowerLetters, numbers, characters",
			args: args{
				input:  lowerLetters + numbers + characters,
				spaces: false,
			},
			want: lowerLetters,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Alpha(tt.args.input, tt.args.spaces); got != tt.want {
				t.Errorf("Alpha() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlphaNumeric(t *testing.T) {
	type args struct {
		input  string
		spaces bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test lower, upper and numbers",
			args: args{
				input:  lowerLetters + upperLetters + numbers,
				spaces: true,
			},
			want: lowerLetters + upperLetters + numbers,
		},
		{
			name: "Test lower, upper, numbers and special characters",
			args: args{
				input:  lowerLetters + upperLetters + numbers + characters,
				spaces: true,
			},
			want: lowerLetters + upperLetters + numbers,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AlphaNumeric(tt.args.input, tt.args.spaces); got != tt.want {
				t.Errorf("AlphaNumeric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTML(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test Removing HTML tags",
			args: args{
				input: htmlOpeningCharacters + lowerLetters + htmlClosingCharacters,
			},
			want: lowerLetters,
		},
		{
			name: "Test only text, numbers and special characters",
			args: args{
				input: upperLetters + lowerLetters + characters + numbers,
			},
			want: upperLetters + lowerLetters + characters + numbers,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTML(tt.args.input); got != tt.want {
				t.Errorf("HTML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXML(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test Removing xml tags",
			args: args{
				input: xmlOpeningCharacters + lowerLetters + xmlClosingCharacters,
			},
			want: lowerLetters,
		},
		{
			name: "Test only text, numbers and special characters",
			args: args{
				input: upperLetters + lowerLetters + characters + numbers,
			},
			want: upperLetters + lowerLetters + characters + numbers,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := XML(tt.args.input); got != tt.want {
				t.Errorf("XML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHtmlEscape(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test escaping html",
			args: args{
				input: htmlOpeningCharacters + lowerLetters + htmlClosingCharacters,
			},
			want: "&lt;html&gt;&lt;body&gt;&lt;h1&gt;abcdefghijklmnopqrstuwxyz&lt;/h1&gt;&lt;/body&gt;&lt;/html&gt;",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HtmlEscape(tt.args.input); got != tt.want {
				t.Errorf("HtmlEscape() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScripts(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test script tags",
			args: args{
				input: scriptOpening + scriptDocument + scriptClosing,
			},
			want: "",
		},
		{
			name: "Test embedded tags",
			args: args{
				input: embedOpening + scriptDocument + embedClosing,
			},
			want: "",
		},
		{
			name: "Test object tags",
			args: args{
				input: objectOpening + scriptDocument + objectClosing,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Scripts(tt.args.input); got != tt.want {
				t.Errorf("Scripts() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Need to include more use cases
func TestXSS(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test XSS attack",
			args: args{
				input: lowerLetters + XSSTest + upperLetters,
			},
			want: lowerLetters + upperLetters,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := XSS(tt.args.input); got != tt.want {
				t.Errorf("XSS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Need to test for unknown URIs
func TestURI(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test URI, url schema",
			args: args{
				input: uriTestUrl,
			},
			want: uriTestUrl,
		},
		{
			name: "Test URI, mail schema",
			args: args{
				input: uriTestEmail,
			},
			want: uriTestEmail,
		},
		{
			name: "Test URI, tel schema",
			args: args{
				input: uriTestTelephone,
			},
			want: uriTestTelephone,
		},
		{
			name: "Test URI, Geolocation schema",
			args: args{
				input: uriTestGeo,
			},
			want: uriTestGeo,
		},
		{
			name: "Test URI, FTP schema",
			args: args{
				input: uriTestFtp,
			},
			want: uriTestFtp,
		},
		{
			name: "Test URI, News schema",
			args: args{
				input: uriTestNews,
			},
			want: uriTestNews,
		},
		{
			name: "Test URI, Data schema",
			args: args{
				input: uriTestData,
			},
			want: uriTestData,
		},
		{
			name: "Test URI, File schema",
			args: args{
				input: uriTestFile,
			},
			want: uriTestFile,
		},
		{
			name: "Test URI, Bitcoin schema",
			args: args{
				input: uriTestBitcoin,
			},
			want: uriTestBitcoin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := URI(tt.args.input); got != tt.want {
				t.Errorf("URI() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Need to test for unknown URLs
func TestURL(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test URL",
			args: args{
				input: URLTest,
			},
			want: URLTest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := URL(tt.args.input, true); got != tt.want {
				t.Errorf("URL() = %v, want %v", got, tt.want)
			}
		})
	}
}
