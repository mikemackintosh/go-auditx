package bsm

// Token is the base audit record
type Token struct {
	Arg     []Arg `json:"arg,omitempty" xml:"arg"`
	Header  `json:"header,omitempty" xml:"header"`
	Path    []Path `json:"path,omitempty" xml:"path"`
	Return  `json:"return,omitempty" xml:"return"`
	Socket  `json:"socket,omitempty" xml:"socket"`
	Subject `json:"subject,omitempty" xml:"subject"`
	Text    []Text `json:"text,omitempty" xml:"text"`
	Trailer `json:"trailer,omitempty" xml:"trailer"`
}
