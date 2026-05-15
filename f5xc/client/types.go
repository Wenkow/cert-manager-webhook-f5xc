package client

import "fmt"

type APIRRSet struct {
	DNSZoneName string `json:"dns_zone_name,omitempty"`
	GroupName   string `json:"group_name,omitempty"`
	RecordName  string `json:"record_name,omitempty"`
	Type        string `json:"type,omitempty"`
	RRSet       RRSet  `json:"rrset"`
}

type RRSet struct {
	Description string     `json:"description,omitempty"`
	TTL         int        `json:"ttl,omitempty"`
	TXTRecord   *TXTRecord `json:"txt_record,omitempty"`
}

type TXTRecord struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values,omitempty"`
}

type APIError struct {
	StatusCode int      `json:"-"`
	Code       int      `json:"code"`
	Message    string   `json:"message"`
	Details    []string `json:"details"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("f5xc: API error code %d: %s", e.Code, e.Message)
}
