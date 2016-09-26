package bsm

type Token struct {
	Arg     []Arg `json:"arg" xml:"arg"`
	Header  `json:"header" xml:"header"`
	Return  `json:"return" xml:"return"`
	Socket  `json:"socket" xml:"socket"`
	Subject `json:"subject" xml:"subject"`
	Text    []Text `json:"text" xml:"text"`
	Trailer `json:"trailer" xml:"trailer"`
}
