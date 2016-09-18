package bsm

type Token struct {
	Header  `json:"header" xml:"header"`
	Subject `json:"subject" xml:"subject"`
	Arg     `json:"arg" xml:"arg"`
	Text    []Text `json:"text" xml:"text"`
	Return  `json:"return" xml:"return"`
	Trailer `json:"trailer" xml:"trailer"`
}
