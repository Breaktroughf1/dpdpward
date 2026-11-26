// Package model holds the types shared by dpdpward's extractors, classifier
// and analysis.
package model

// Store is a place where records are kept: a SQL table, an ORM model, a
// document schema or a struct persisted to a database.
type Store struct {
	Name   string  `json:"name"`   // table or model name
	Kind   string  `json:"kind"`   // sql-table, prisma-model, django-model, ...
	File   string  `json:"file"`   // path relative to the scan root
	Line   int     `json:"line"`   // line of the declaration
	Fields []Field `json:"fields"` // columns or attributes
}

// Field is one column or attribute of a store.
type Field struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	Line int    `json:"line"`
}

// Sensitivity levels for personal data elements.
const (
	SensLow    = "low"
	SensMedium = "medium"
	SensHigh   = "high"
)

// Element is a field classified as personal data.
type Element struct {
	Store       string `json:"store"`
	StoreKind   string `json:"store_kind"`
	Field       string `json:"field"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Category    string `json:"category"`    // e.g. government-id.aadhaar
	Label       string `json:"label"`       // human label, e.g. Aadhaar number
	Sensitivity string `json:"sensitivity"` // low | medium | high
	Confidence  string `json:"confidence"`  // low | medium | high
	Children    bool   `json:"children_indicator,omitempty"`
	Reason      string `json:"reason"`
}

// ValueHit is an identifier-like value found in source, fixtures or config.
type ValueHit struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Kind     string `json:"kind"`     // aadhaar | pan | gstin | upi
	Redacted string `json:"redacted"` // the value with most characters masked
	Checksum bool   `json:"checksum_valid"`
}
